# TearGame API 文档

## 目录

1. [概述](#概述)
2. [快速开始](#快速开始)
3. [C API](#c-api)
4. [C++ API](#c-api-1)
5. [批量操作](#批量操作)
6. [指针链读取](#指针链读取)
7. [隐藏功能](#隐藏功能)
8. [触控模拟](#触控模拟)
9. [错误处理](#错误处理)
10. [最佳实践](#最佳实践)
11. [常见问题](#常见问题)

---

## 概述

TearGame 是一个 ARM64 Linux 内核模块，提供：
- 高性能进程内存读写
- 进程/文件内核级隐藏
- 虚拟触控设备模拟
- 安全的反作弊绕过机制

### 支持的内核版本
- Linux 5.10+
- ARM64 架构

### 通信机制
通过 `prctl` 系统调用与内核模块通信，使用动态魔数验证身份。

---

## 快速开始

### C 语言

```c
#include <teargame_user.h>

int main() {
    // 1. 检查模块是否加载
    if (!tear_is_loaded()) {
        printf("模块未加载\n");
        return 1;
    }
    
    // 2. 认证
    if (tear_auth("MyApp") != 0) {
        printf("认证失败\n");
        return 1;
    }
    
    // 3. 查找目标进程
    int pid = tear_find_pid("com.game.target");
    if (pid <= 0) {
        printf("进程未找到\n");
        return 1;
    }
    
    // 4. 读取内存
    int health = tear_read_i32(pid, 0x12345678);
    printf("血量: %d\n", health);
    
    // 5. 写入内存
    tear_write_i32(pid, 0x12345678, 999);
    
    return 0;
}
```

### C++

```cpp
#include <teargame.hpp>

int main() {
    teargame::TearGame tear;
    
    // 认证并附加
    if (!tear.auth("MyApp") || !tear.attach("com.game.target")) {
        std::cerr << "初始化失败: " << tear.lastErrorString() << "\n";
        return 1;
    }
    
    // 读取
    auto health = tear.read<int>(0x12345678);
    
    // 指针链读取
    auto value = tear.readChain<float>(base, {0x10, 0x20, 0x30});
    
    // 写入
    tear.write(0x12345678, 999);
    
    return 0;
}
```

---

## C API

### 初始化函数

#### `tear_is_loaded()`
检查 TearGame 内核模块是否已加载。

```c
int tear_is_loaded(void);
```
- **返回**: 1 = 已加载, 0 = 未加载

#### `tear_auth(magic)`
使用魔术字符串进行认证。

```c
int tear_auth(const char *magic);
```
- **参数**: `magic` - 任意字符串，用于生成认证密钥
- **返回**: 0 = 成功, 负数 = 失败

### 进程函数

#### `tear_find_pid(name)`
按进程名查找 PID。

```c
int tear_find_pid(const char *name);
```
- **参数**: `name` - 进程名（可以是完整名或部分匹配）
- **返回**: PID, 0 = 未找到

#### `tear_find_pid_stealth(name)`
使用缓存查找 PID（更隐蔽，减少系统调用）。

```c
int tear_find_pid_stealth(const char *name);
```

### 内存读取

#### `tear_read(pid, addr, buffer, size)`
读取目标进程内存。

```c
int tear_read(int pid, uint64_t addr, void *buffer, size_t size);
```
- **返回**: 0 = 成功, 负数 = 失败

#### 类型安全宏

```c
// 整数读取
int8_t   tear_read_i8(pid, addr)
int16_t  tear_read_i16(pid, addr)
int32_t  tear_read_i32(pid, addr)
int64_t  tear_read_i64(pid, addr)
uint8_t  tear_read_u8(pid, addr)
uint16_t tear_read_u16(pid, addr)
uint32_t tear_read_u32(pid, addr)
uint64_t tear_read_u64(pid, addr)

// 浮点读取
float  tear_read_f32(pid, addr)
double tear_read_f64(pid, addr)

// 指针读取 (64位)
uint64_t tear_read_ptr(pid, addr)
```

#### `tear_read_string(pid, addr, buffer, maxlen)`
读取字符串。

```c
int tear_read_string(int pid, uint64_t addr, char *buffer, size_t maxlen);
```
- **返回**: 字符串长度, -1 = 失败

### 内存写入

#### `tear_write(pid, addr, buffer, size)`
写入目标进程内存。

```c
int tear_write(int pid, uint64_t addr, void *buffer, size_t size);
```

#### 类型安全宏

```c
// 整数写入
tear_write_i8(pid, addr, val)
tear_write_i16(pid, addr, val)
tear_write_i32(pid, addr, val)
tear_write_i64(pid, addr, val)
tear_write_u8(pid, addr, val)
tear_write_u16(pid, addr, val)
tear_write_u32(pid, addr, val)
tear_write_u64(pid, addr, val)

// 浮点写入
tear_write_f32(pid, addr, val)
tear_write_f64(pid, addr, val)
```

### 模块函数

#### `tear_get_module_base(pid, name)`
获取模块基地址。

```c
uint64_t tear_get_module_base(int pid, const char *name);
```
- **参数**: `name` - 模块名（如 "libil2cpp.so"）
- **返回**: 基地址, 0 = 未找到

---

## C++ API

### TearGame 类

```cpp
namespace teargame {

class TearGame {
public:
    // 初始化
    bool isLoaded();
    bool auth(const std::string& magic);
    bool attach(int pid);
    bool attach(const std::string& name);
    
    // 状态
    bool isAuthenticated() const;
    bool isAttached() const;
    int pid() const;
    
    // 读取
    template<typename T> T read(uint64_t addr);
    template<typename T> T readSafe(uint64_t addr);
    bool readBuffer(uint64_t addr, void* buffer, size_t size);
    std::vector<uint8_t> readBytes(uint64_t addr, size_t size);
    std::string readString(uint64_t addr, size_t maxLen = 256);
    
    // 指针链读取
    template<typename T> T readChain(uint64_t base, std::initializer_list<uint64_t> offsets);
    template<typename T> T readChain(uint64_t base, const std::vector<uint64_t>& offsets);
    uint64_t resolveChain(uint64_t base, std::initializer_list<uint64_t> offsets);
    
    // 写入
    template<typename T> bool write(uint64_t addr, const T& value);
    template<typename T> bool writeSafe(uint64_t addr, const T& value);
    bool writeBuffer(uint64_t addr, const void* buffer, size_t size);
    
    // 批量操作
    std::vector<ReadResult> readBatch(const std::vector<ReadRequest>& requests);
    std::vector<ReadResult> readScatter(const std::vector<ReadRequest>& requests);
    
    // 模块
    uint64_t getModuleBase(const std::string& name);
    MemoryRegion module(const std::string& name);
    
    // 隐藏
    bool hideFile(const std::string& name);
    bool unhideFile(const std::string& name);
    bool hideProcess(int pid);
    bool hideProcess(const std::string& name);
    bool unhideProcess(int pid);
    bool hideSelf();
    
    // 触控
    TouchDevice& touch();
    
    // 错误处理
    Error lastError() const;
    std::string lastErrorString() const;
    void setThrowExceptions(bool enable);
};

}
```

### 使用示例

```cpp
TearGame tear;
tear.setThrowExceptions(true);  // 启用异常模式

try {
    tear.auth("MyApp");
    tear.attach("com.game.target");
    
    // 获取模块基址
    auto base = tear.getModuleBase("libil2cpp.so");
    
    // 指针链读取血量
    // 相当于 [[[base + 0x100] + 0x20] + 0x48]
    auto health = tear.readChain<int>(base, {0x100, 0x20, 0x48});
    
    // 修改血量
    auto healthAddr = tear.resolveChain(base, {0x100, 0x20, 0x48});
    tear.write(healthAddr, 9999);
    
} catch (const TearException& e) {
    std::cerr << "错误: " << e.what() << "\n";
}
```

---

## 批量操作

批量操作可以显著提高性能，特别是在需要读取多个不连续地址时。

### C API

```c
// 批量读取
struct tear_batch_item items[] = {
    {0x12345678, 4, 0},  // 读取4字节
    {0x12345700, 8, 0},  // 读取8字节
};

char buffer[12];
tear_read_batch(pid, items, 2, buffer, sizeof(buffer));

// 分散读取（每个条目独立缓冲区）
int health;
float pos_x;

struct tear_scatter_entry entries[] = {
    {addr1, (uint64_t)&health, sizeof(health), 0},
    {addr2, (uint64_t)&pos_x, sizeof(pos_x), 0},
};

tear_read_scatter(pid, entries, 2);
```

### C++ API

```cpp
// 批量读取
std::vector<ReadRequest> requests = {
    {addr1, sizeof(int)},
    {addr2, sizeof(float)},
    {addr3, sizeof(double)},
};

auto results = tear.readBatch(requests);

for (const auto& r : results) {
    if (r.success) {
        std::cout << "地址 " << r.addr << " 读取成功\n";
    }
}

// 获取特定类型
int value = results[0].as<int>();
```

---

## 指针链读取

指针链读取用于处理多级指针，如游戏中的对象结构。

### C API

```c
// 定义偏移量
uint64_t offsets[] = {0x10, 0x20, 0x30, 0x48};

// 获取最终地址
uint64_t final_addr = tear_read_chain(pid, base, offsets, 4);
// 相当于: [[[base + 0x10] + 0x20] + 0x30] + 0x48

// 读取最终值
int value = tear_read_chain_i32(pid, base, offsets, 4);
```

### C++ API

```cpp
// 使用初始化列表
auto health = tear.readChain<int>(base, {0x10, 0x20, 0x48});

// 使用 vector
std::vector<uint64_t> offsets = {0x10, 0x20, 0x48};
auto health = tear.readChain<int>(base, offsets);

// 获取最终地址（不读取值）
auto addr = tear.resolveChain(base, {0x10, 0x20, 0x48});
```

---

## 隐藏功能

### 文件隐藏

隐藏文件或文件夹，使其在 `ls` 等工具中不可见，但仍可正常访问。

```c
// C API
tear_hide_file("secret_folder");      // 隐藏文件夹
tear_hide_file("*.log");              // 隐藏所有 .log 文件
tear_unhide_file("secret_folder");    // 取消隐藏
```

```cpp
// C++ API
tear.hideFile("secret_folder");
tear.unhideFile("secret_folder");
```

### 进程隐藏

隐藏进程，使其在 `ps`、`top`、`/proc` 中不可见，但仍正常运行。

```c
// C API
tear_hide_process(pid);               // 按 PID 隐藏
tear_hide_process_name("my_app");     // 按名称隐藏
tear_hide_self();                     // 隐藏当前进程
tear_unhide_process(pid);             // 取消隐藏
```

```cpp
// C++ API
tear.hideProcess(pid);
tear.hideProcess("my_app");
tear.hideSelf();
tear.unhideProcess(pid);
```

---

## 触控模拟

### 初始化

```c
// C API
tear_touch_init(1080, 2400);  // 设置屏幕分辨率
```

```cpp
// C++ API
tear.touch().init(1080, 2400);
```

### 基本操作

```c
// 点击
tear_touch_tap(540, 1200, 50);  // 点击 (540, 1200)，延迟 50ms

// 滑动
tear_touch_swipe(100, 500, 900, 500, 20, 500);
// 从 (100, 500) 滑动到 (900, 500)，20步，500ms
```

```cpp
// C++ API
tear.touch().tap(540, 1200, 50);
tear.touch().swipe(100, 500, 900, 500, 20, 500);
```

### 多点触控

```c
// 手动控制触控点
tear_touch_down(0, 100, 100);   // 第0个手指按下
tear_touch_down(1, 200, 200);   // 第1个手指按下
tear_touch_move(0, 150, 150);   // 移动第0个手指
tear_touch_up(0);               // 第0个手指抬起
tear_touch_up(1);               // 第1个手指抬起
```

---

## 错误处理

### C API

大多数函数返回:
- `0` = 成功
- 负数 = 错误码

```c
int ret = tear_read(pid, addr, buffer, size);
if (ret != 0) {
    printf("读取失败: %d\n", ret);
}
```

### C++ API

两种模式:

#### 错误码模式（默认）

```cpp
TearGame tear;
auto value = tear.read<int>(addr);
if (tear.lastError() != teargame::Error::None) {
    std::cerr << "错误: " << tear.lastErrorString() << "\n";
}
```

#### 异常模式

```cpp
TearGame tear;
tear.setThrowExceptions(true);

try {
    auto value = tear.read<int>(addr);
} catch (const TearException& e) {
    std::cerr << "异常: " << e.what() << "\n";
}
```

---

## 最佳实践

### 1. 使用批量操作

当需要读取多个值时，使用批量操作而非多次单独调用：

```cpp
// 不推荐
auto a = tear.read<int>(addr1);
auto b = tear.read<int>(addr2);
auto c = tear.read<int>(addr3);

// 推荐
auto results = tear.readBatch({
    {addr1, sizeof(int)},
    {addr2, sizeof(int)},
    {addr3, sizeof(int)},
});
```

### 2. 缓存进程 ID 和模块基址

```cpp
// 在初始化时获取，然后缓存
int pid = tear.findPid("com.game.target");
uint64_t base = tear.getModuleBase("libil2cpp.so");

// 之后直接使用缓存的值
auto value = tear.read<int>(base + 0x100);
```

### 3. 使用安全读写

在不确定地址是否有效时，使用安全版本：

```cpp
auto value = tear.readSafe<int>(addr);  // 不会崩溃
```

### 4. 隐藏自身

在需要隐蔽的场景下：

```cpp
tear.hideSelf();           // 隐藏进程
tear.hideFile("my_app");   // 隐藏可执行文件
```

---

## 常见问题

### Q: 模块无法加载？

确保:
1. 内核版本 >= 5.10
2. 架构为 ARM64
3. 已禁用安全启动或签名模块

### Q: 认证失败？

1. 确保系统时间正确
2. 认证有时间窗口限制（±30秒）

### Q: 读取返回0？

可能原因:
1. 地址无效
2. 目标进程已退出
3. 内存区域有保护
4. 遇到反作弊陷阱

### Q: 性能不够好？

1. 使用批量读取
2. 减少读取频率
3. 缓存不变的数据
