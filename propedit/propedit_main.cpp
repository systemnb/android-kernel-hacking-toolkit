#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <cstdint>
#include <vector>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define PROP_NAME_MAX   32*2
#define PROP_VALUE_MAX  92

struct prop_info {
    uint32_t serial;
    char value[PROP_VALUE_MAX];
    char name[];
};

// ioctl command definitions (same as kernel)
#define PROP_IOC_MAGIC  'P'
#define PROP_IOC_WRITE  _IOW(PROP_IOC_MAGIC, 2, struct prop_write_args)

struct prop_write_args {
    uint64_t value_addr;   // user space address of the target value field
    char new_value[PROP_VALUE_MAX];
};

/**
 * Structure to hold a mapped property region.
 */
struct PropRegion {
    uintptr_t start;
    uintptr_t end;
    void* mapping;         // for later unmapping
    size_t size;
    int fd;
};

/**
 * Open and memory-map all files under /dev/__properties__/.
 * Returns a vector of PropRegion describing each mapped region.
 */
std::vector<PropRegion> map_prop_regions() {
    std::vector<PropRegion> regions;
    const char* prop_dir = "/dev/__properties__/";
    DIR* dir = opendir(prop_dir);
    if (!dir) {
        std::cerr << "Failed to open " << prop_dir << std::endl;
        return regions;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_REG) continue;  // only regular files
        std::string full_path = std::string(prop_dir) + entry->d_name;
        int fd = open(full_path.c_str(), O_RDONLY);
        if (fd < 0) {
            std::cerr << "Cannot open " << full_path << std::endl;
            continue;
        }
        struct stat st;
        if (fstat(fd, &st) != 0) {
            std::cerr << "fstat failed for " << full_path << std::endl;
            close(fd);
            continue;
        }
        if (st.st_size == 0) {
            close(fd);
            continue;
        }
        void* mapping = mmap(nullptr, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
        if (mapping == MAP_FAILED) {
            std::cerr << "mmap failed for " << full_path << std::endl;
            close(fd);
            continue;
        }
        PropRegion region;
        region.start = reinterpret_cast<uintptr_t>(mapping);
        region.end = region.start + st.st_size;
        region.mapping = mapping;
        region.size = st.st_size;
        region.fd = fd;
        regions.push_back(region);
    }
    closedir(dir);
    return regions;
}

/**
 * Unmap all previously mapped property regions.
 */
void unmap_prop_regions(std::vector<PropRegion>& regions) {
    for (auto& region : regions) {
        munmap(region.mapping, region.size);
        close(region.fd);
    }
}

/**
 * Scan a mapped memory region to find a property by its name.
 * Returns a pointer to the prop_info if found, nullptr otherwise.
 */
prop_info* find_prop_in_region(const PropRegion& region, const char* target_key) {
    char* base = reinterpret_cast<char*>(region.start);
    size_t area_size = region.end - region.start;

    // Heuristic scan: assume prop_info structures are aligned and appear
    // sequentially. We step by 4 bytes as a conservative alignment.
    for (size_t off = 0; off + sizeof(prop_info) <= area_size; off += 4) {
        prop_info* candidate = reinterpret_cast<prop_info*>(base + off);
        // Skip if serial is zero (unused slot)
        if (candidate->serial == 0) continue;

        // Check that the name pointer is within the mapped region
        char* name_ptr = candidate->name;
        if (name_ptr < base || name_ptr >= base + area_size) continue;

        // Check name length
        size_t name_len = strnlen(name_ptr, area_size - (name_ptr - base));
        if (name_len == 0 || name_len >= PROP_NAME_MAX) continue;

        // Compare with target key
        if (strcmp(name_ptr, target_key) == 0) {
            return candidate;
        }
    }
    return nullptr;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <key> <value>" << std::endl;
        return 1;
    }

    const char* key = argv[1];
    const char* value = argv[2];

    if (strlen(key) >= PROP_NAME_MAX) {
        std::cerr << "Key too long" << std::endl;
        return 1;
    }
    if (strlen(value) >= PROP_VALUE_MAX) {
        std::cerr << "Value too long" << std::endl;
        return 1;
    }

    // Map all property files
    std::vector<PropRegion> regions = map_prop_regions();
    if (regions.empty()) {
        std::cerr << "No property regions found." << std::endl;
        return 1;
    }

    // Search for the target property in all mapped regions
    prop_info* info = nullptr;
    for (const auto& region : regions) {
        info = find_prop_in_region(region, key);
        if (info) break;
    }

    if (!info) {
        std::cerr << "Property '" << key << "' not found in any region." << std::endl;
        unmap_prop_regions(regions);
        return 1;
    }

    // Compute address of the value field (relative to the mapping)
    uint64_t value_addr = reinterpret_cast<uint64_t>(info->value);
    std::cout << "Found '" << key << "' at value_addr = 0x" << std::hex << value_addr << std::dec << std::endl;
    std::cout << "Current value: " << info->value << std::endl;

    // Open the kernel driver device
    int fd = open("/dev/propedit", O_RDWR);
    if (fd < 0) {
        perror("open /dev/propedit failed");
        unmap_prop_regions(regions);
        return 1;
    }

    struct prop_write_args args;
    args.value_addr = value_addr;
    strncpy(args.new_value, value, PROP_VALUE_MAX - 1);
    args.new_value[PROP_VALUE_MAX - 1] = '\0';

    if (ioctl(fd, PROP_IOC_WRITE, &args) < 0) {
        perror("ioctl failed");
        close(fd);
        unmap_prop_regions(regions);
        return 1;
    }

    close(fd);
    std::cout << "Property updated successfully." << std::endl;

    // Verification using getprop command
    std::string cmd = "getprop " + std::string(key);
    std::cout << "Running: " << cmd << std::endl;
    system(cmd.c_str());

    // Clean up mappings
    unmap_prop_regions(regions);
    return 0;
}