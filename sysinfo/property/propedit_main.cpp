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

// Find all property regions
std::vector<std::pair<uintptr_t, uintptr_t>> find_prop_areas() {
    std::vector<std::pair<uintptr_t, uintptr_t>> areas;
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        uintptr_t start, end;
        char perms[5], path[256];
        int matched = sscanf(line.c_str(), "%lx-%lx %4s %*s %*s %*d %255s", &start, &end, perms, path);
        if (matched >= 4 && strstr(path, "/dev/__properties__/") != nullptr) {
            areas.emplace_back(start, end);
        }
    }
    return areas;
}

// Scan memory to find the target property
prop_info* find_prop_by_scan(uintptr_t start, uintptr_t end, const char* target_key) {
    char* base = reinterpret_cast<char*>(start);
    size_t area_size = end - start;
    for (size_t off = 0; off + sizeof(prop_info) <= area_size; off += 4) {
        prop_info* candidate = reinterpret_cast<prop_info*>(base + off);
        if (candidate->serial == 0) continue;
        char* name_ptr = candidate->name;
        if (name_ptr < base || name_ptr >= base + area_size) continue;
        size_t name_len = strnlen(name_ptr, area_size - (name_ptr - base));
        if (name_len == 0 || name_len >= PROP_NAME_MAX) continue;
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

    auto areas = find_prop_areas();
    if (areas.empty()) {
        std::cerr << "No prop area found" << std::endl;
        return 1;
    }

    prop_info* info = nullptr;
    for (const auto& area : areas) {
        info = find_prop_by_scan(area.first, area.second, key);
        if (info) break;
    }

    if (!info) {
        std::cerr << "Property '" << key << "' not found" << std::endl;
        return 1;
    }

    // Compute address of the value field
    uint64_t value_addr = reinterpret_cast<uint64_t>(info->value);
    std::cout << "Found '" << key << "' at value_addr = 0x" << std::hex << value_addr << std::dec << std::endl;
    std::cout << "Current value: " << info->value << std::endl;

    // Open the driver device
    int fd = open("/dev/propedit", O_RDWR);
    if (fd < 0) {
        perror("open /dev/propedit failed");
        return 1;
    }

    struct prop_write_args args;
    args.value_addr = value_addr;
    strncpy(args.new_value, value, PROP_VALUE_MAX - 1);
    args.new_value[PROP_VALUE_MAX - 1] = '\0';

    if (ioctl(fd, PROP_IOC_WRITE, &args) < 0) {
        perror("ioctl failed");
        close(fd);
        return 1;
    }

    close(fd);
    std::cout << "Property updated successfully" << std::endl;

    // Verification
    std::string cmd = "getprop " + std::string(key);
    std::cout << "Running: " << cmd << std::endl;
    system(cmd.c_str());

    return 0;
}