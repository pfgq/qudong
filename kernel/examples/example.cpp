/*
 * TearGame C++ 示例程序
 * 
 * 演示如何使用 TearGame C++ 库
 * 编译: g++ -std=c++17 -o example example.cpp
 */

#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <chrono>

// 包含 TearGame C++ 头文件
#include "../include/teargame.hpp"

// 认证魔数（需要与内核模块配置匹配）
constexpr const char* AUTH_MAGIC = "MyApplication";

// 辅助函数：打印十六进制数据
void printHex(const std::vector<uint8_t>& data, size_t maxLen = 64) {
    size_t len = std::min(data.size(), maxLen);
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(data[i]) << " ";
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
    if (len % 16 != 0) std::cout << std::endl;
    if (data.size() > maxLen) {
        std::cout << "... (" << std::dec << (data.size() - maxLen) << " more bytes)" << std::endl;
    }
    std::cout << std::dec;
}

// 示例1：基本读写操作
void exampleBasicReadWrite(TearGame& tear) {
    std::cout << "\n=== 示例1: 基本读写操作 ===" << std::endl;
    
    // 假设目标地址（实际使用时需要替换为有效地址）
    uint64_t addr = 0x12345678;
    
    // 模板化读取
    int intValue = tear.read<int>(addr);
    std::cout << "读取 int: " << intValue << std::endl;
    
    float floatValue = tear.read<float>(addr);
    std::cout << "读取 float: " << floatValue << std::endl;
    
    // 读取字节数组
    auto bytes = tear.readBytes(addr, 16);
    std::cout << "读取 16 字节:" << std::endl;
    printHex(bytes);
    
    // 写入示例（注释掉以防止意外修改）
    // tear.write<int>(addr, 100);
    // tear.write<float>(addr, 3.14f);
}

// 示例2：批量读取
void exampleBatchRead(TearGame& tear) {
    std::cout << "\n=== 示例2: 批量读取 ===" << std::endl;
    
    // 定义多个读取请求
    std::vector<teargame::ReadRequest> requests = {
        {0x1000, sizeof(int)},
        {0x2000, sizeof(float)},
        {0x3000, 16},
        {0x4000, 32}
    };
    
    // 计时
    auto start = std::chrono::high_resolution_clock::now();
    
    // 执行批量读取
    auto results = tear.readBatch(requests);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "批量读取 " << results.size() << " 个地址，耗时: " 
              << duration.count() << " 微秒" << std::endl;
    
    // 处理结果
    for (size_t i = 0; i < results.size(); i++) {
        const auto& r = results[i];
        std::cout << "  [" << i << "] 地址 0x" << std::hex << r.addr << std::dec;
        
        if (r.success) {
            std::cout << " - 成功，" << r.data.size() << " 字节";
            
            // 根据大小显示不同类型
            if (r.data.size() == sizeof(int)) {
                std::cout << " = " << r.as<int>();
            } else if (r.data.size() == sizeof(float)) {
                std::cout << " = " << r.as<float>() << "f";
            }
        } else {
            std::cout << " - 失败，错误码: " << r.error;
        }
        std::cout << std::endl;
    }
}

// 示例3：分散读取
void exampleScatterRead(TearGame& tear) {
    std::cout << "\n=== 示例3: 分散读取 ===" << std::endl;
    
    std::vector<teargame::ReadRequest> requests = {
        {0x10000, 64},
        {0x20000, 128},
        {0x30000, 256}
    };
    
    auto results = tear.readScatter(requests);
    
    std::cout << "分散读取结果:" << std::endl;
    for (const auto& r : results) {
        std::cout << "  地址 0x" << std::hex << r.addr << std::dec 
                  << ": " << (r.success ? "成功" : "失败")
                  << " (" << r.data.size() << " 字节)" << std::endl;
    }
}

// 示例4：模块操作
void exampleModuleOps(TearGame& tear) {
    std::cout << "\n=== 示例4: 模块操作 ===" << std::endl;
    
    // 获取模块基址
    std::string moduleName = "libil2cpp.so";
    uint64_t base = tear.getModuleBase(moduleName);
    
    if (base != 0) {
        std::cout << "模块 " << moduleName << " 基址: 0x" 
                  << std::hex << base << std::dec << std::endl;
        
        // 使用 MemoryRegion 进行相对偏移读取
        auto region = tear.module(moduleName);
        if (region) {
            // 读取模块头部（ELF magic）
            auto header = region.readBytes(0, 4);
            std::cout << "模块头部: ";
            printHex(header);
            
            // 读取偏移处的值
            int value = region.read<int>(0x1234);
            std::cout << "偏移 0x1234 处的值: " << value << std::endl;
        }
    } else {
        std::cout << "未找到模块: " << moduleName << std::endl;
    }
}

// 示例5：触控操作
void exampleTouch(TearGame& tear) {
    std::cout << "\n=== 示例5: 触控操作 ===" << std::endl;
    
    auto& touch = tear.touch();
    
    // 初始化触控设备
    if (touch.init(1080, 2400)) {
        std::cout << "触控设备已初始化: " << touch.width() << "x" << touch.height() << std::endl;
        
        // 模拟点击
        std::cout << "模拟点击 (540, 1200)..." << std::endl;
        touch.tap(540, 1200, 50);
        
        // 模拟滑动
        std::cout << "模拟滑动 (100, 500) -> (900, 500)..." << std::endl;
        touch.swipe(100, 500, 900, 500, 20, 300);
        
        // 多点触控示例
        std::cout << "多点触控..." << std::endl;
        touch.down(0, 200, 800);
        touch.down(1, 800, 800);
        usleep(100000);  // 100ms
        touch.move(0, 300, 900);
        touch.move(1, 700, 900);
        usleep(100000);
        touch.up(0);
        touch.up(1);
        
    } else {
        std::cout << "触控设备初始化失败" << std::endl;
    }
}

// 示例6：异常模式
void exampleExceptions() {
    std::cout << "\n=== 示例6: 异常模式 ===" << std::endl;
    
    TearGame tear;
    tear.setThrowExceptions(true);  // 启用异常
    
    try {
        // 未认证时尝试操作会抛出异常
        tear.attach("some_process");
        
    } catch (const TearException& e) {
        std::cout << "捕获异常: " << e.what() << std::endl;
        std::cout << "错误类型: " << static_cast<int>(e.error) << std::endl;
    }
}

// 示例7：快速工厂函数
void exampleFactory() {
    std::cout << "\n=== 示例7: 工厂函数 ===" << std::endl;
    
    // 方式1：仅认证
    auto tear1 = teargame::make_teargame(AUTH_MAGIC);
    if (tear1) {
        std::cout << "方式1: 认证成功" << std::endl;
    } else {
        std::cout << "方式1: 认证失败" << std::endl;
    }
    
    // 方式2：认证并附加进程
    auto tear2 = teargame::make_teargame(AUTH_MAGIC, "com.game.target");
    if (tear2) {
        std::cout << "方式2: 认证并附加成功，PID=" << tear2->pid() << std::endl;
    } else {
        std::cout << "方式2: 失败" << std::endl;
    }
}

// 性能测试
void performanceTest(TearGame& tear) {
    std::cout << "\n=== 性能测试 ===" << std::endl;
    
    constexpr int ITERATIONS = 1000;
    constexpr uint64_t TEST_ADDR = 0x10000;
    
    // 单次读取测试
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < ITERATIONS; i++) {
        volatile int val = tear.read<int>(TEST_ADDR);
        (void)val;
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "单次读取 " << ITERATIONS << " 次: " 
              << duration.count() << " 微秒 ("
              << (duration.count() / ITERATIONS) << " 微秒/次)" << std::endl;
    
    // 批量读取测试
    std::vector<teargame::ReadRequest> requests;
    for (int i = 0; i < 16; i++) {
        requests.emplace_back(TEST_ADDR + i * 0x100, sizeof(int));
    }
    
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < ITERATIONS / 16; i++) {
        auto results = tear.readBatch(requests);
        (void)results;
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    int totalReads = (ITERATIONS / 16) * 16;
    std::cout << "批量读取 " << totalReads << " 次 (每批16个): " 
              << duration.count() << " 微秒 ("
              << (duration.count() * 16 / totalReads) << " 微秒/批)" << std::endl;
}

void printUsage(const char* prog) {
    std::cout << "TearGame C++ 示例程序" << std::endl;
    std::cout << "用法: " << prog << " <命令> [参数...]" << std::endl;
    std::cout << std::endl;
    std::cout << "命令:" << std::endl;
    std::cout << "  check           - 检查模块是否加载" << std::endl;
    std::cout << "  auth            - 认证测试" << std::endl;
    std::cout << "  find <name>     - 查找进程PID" << std::endl;
    std::cout << "  demo <pid>      - 运行所有演示" << std::endl;
    std::cout << "  perf <pid>      - 性能测试" << std::endl;
    std::cout << "  read <pid> <addr> [size] - 读取内存" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string cmd = argv[1];
    TearGame tear;
    
    // 检查模块
    if (cmd == "check") {
        if (tear.isLoaded()) {
            std::cout << "TearGame 模块已加载！" << std::endl;
            return 0;
        } else {
            std::cout << "TearGame 模块未加载。" << std::endl;
            return 1;
        }
    }
    
    // 认证测试
    if (cmd == "auth") {
        std::cout << "正在认证..." << std::endl;
        if (tear.auth(AUTH_MAGIC)) {
            std::cout << "认证成功！" << std::endl;
            return 0;
        } else {
            std::cout << "认证失败: " << tear.lastErrorString() << std::endl;
            return 1;
        }
    }
    
    // 查找进程
    if (cmd == "find") {
        if (argc < 3) {
            std::cout << "用法: " << argv[0] << " find <进程名>" << std::endl;
            return 1;
        }
        
        if (!tear.auth(AUTH_MAGIC)) {
            std::cout << "认证失败" << std::endl;
            return 1;
        }
        
        std::string name = argv[2];
        int pid = tear.findPid(name);
        
        if (pid > 0) {
            std::cout << "找到进程: " << name << ", PID=" << pid << std::endl;
            return 0;
        } else {
            std::cout << "未找到进程: " << name << std::endl;
            return 1;
        }
    }
    
    // 读取内存
    if (cmd == "read") {
        if (argc < 4) {
            std::cout << "用法: " << argv[0] << " read <pid> <addr> [size]" << std::endl;
            return 1;
        }
        
        if (!tear.auth(AUTH_MAGIC)) {
            std::cout << "认证失败" << std::endl;
            return 1;
        }
        
        int pid = std::atoi(argv[2]);
        uint64_t addr = std::strtoull(argv[3], nullptr, 0);
        size_t size = (argc > 4) ? std::atoi(argv[4]) : 64;
        
        if (size > 4096) size = 4096;
        
        tear.attach(pid);
        auto data = tear.readBytes(addr, size);
        
        if (!data.empty()) {
            std::cout << "读取 " << data.size() << " 字节 @ 0x" 
                      << std::hex << addr << std::dec << ":" << std::endl;
            printHex(data);
            return 0;
        } else {
            std::cout << "读取失败: " << tear.lastErrorString() << std::endl;
            return 1;
        }
    }
    
    // 运行所有演示
    if (cmd == "demo") {
        if (argc < 3) {
            std::cout << "用法: " << argv[0] << " demo <pid>" << std::endl;
            return 1;
        }
        
        if (!tear.auth(AUTH_MAGIC)) {
            std::cout << "认证失败" << std::endl;
            return 1;
        }
        
        int pid = std::atoi(argv[2]);
        tear.attach(pid);
        
        std::cout << "已附加进程 PID=" << pid << std::endl;
        
        exampleBasicReadWrite(tear);
        exampleBatchRead(tear);
        exampleScatterRead(tear);
        exampleModuleOps(tear);
        exampleTouch(tear);
        exampleExceptions();
        exampleFactory();
        
        return 0;
    }
    
    // 性能测试
    if (cmd == "perf") {
        if (argc < 3) {
            std::cout << "用法: " << argv[0] << " perf <pid>" << std::endl;
            return 1;
        }
        
        if (!tear.auth(AUTH_MAGIC)) {
            std::cout << "认证失败" << std::endl;
            return 1;
        }
        
        int pid = std::atoi(argv[2]);
        tear.attach(pid);
        
        performanceTest(tear);
        return 0;
    }
    
    std::cout << "未知命令: " << cmd << std::endl;
    printUsage(argv[0]);
    return 1;
}
