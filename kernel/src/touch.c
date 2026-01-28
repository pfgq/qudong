// SPDX-License-Identifier: GPL-2.0
/*
 * TearGame 虚拟触控设备
 * 
 * 多点触控输入设备模拟，具有:
 * - 读写锁优化并发访问
 * - 正确的输入事件序列
 * - 多点触控槽位跟踪
 */

#include "teargame.h"
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/delay.h>

/*
 * ============================================================================
 * 触控设备状态
 * ============================================================================
 */
static struct tear_touch_device touch_dev = {
    .input = NULL,
    .initialized = false,
    .width = TEAR_TOUCH_DEFAULT_WIDTH,
    .height = TEAR_TOUCH_DEFAULT_HEIGHT,
    .debug = TEAR_TOUCH_DEBUG_DEFAULT,
};

/*
 * ============================================================================
 * 私有辅助函数
 * ============================================================================
 */

/*
 * 检查设备是否已准备好使用
 */
static inline bool touch_is_ready(void)
{
    return touch_dev.initialized && touch_dev.input != NULL;
}

/*
 * 调试打印辅助
 */
static inline void touch_dbg(const char *fmt, ...)
{
    if (touch_dev.debug) {
        va_list args;
        va_start(args, fmt);
        vprintk(fmt, args);
        va_end(args);
    }
}

/*
 * ============================================================================
 * 公共API
 * ============================================================================
 */

/*
 * 初始化触控模块（模块加载时调用）
 */
int teargame_touch_module_init(void)
{
    int i;
    
    mutex_init(&touch_dev.lock);
    rwlock_init(&touch_dev.rwlock);
    
    /* 初始化槽位状态 */
    for (i = 0; i < TEAR_TOUCH_MAX_SLOTS; i++) {
        touch_dev.slots[i].down = false;
        touch_dev.slots[i].x = 0;
        touch_dev.slots[i].y = 0;
        touch_dev.slots[i].pressure = TEAR_TOUCH_DEFAULT_PRESSURE;
        touch_dev.slots[i].down_time = 0;
    }
    
    atomic_set(&touch_dev.down_count, 0);
    atomic_set(&touch_dev.total_down, 0);
    atomic_set(&touch_dev.total_up, 0);
    
    tear_info("触控模块已初始化\n");
    tear_info("  最大槽位: %d\n", TEAR_TOUCH_MAX_SLOTS);
    tear_info("  调试模式: %s\n", touch_dev.debug ? "启用" : "禁用");
    
    return 0;
}

/*
 * 清理触控模块
 */
void teargame_touch_module_exit(void)
{
    touch_dbg("[TearGame] 触控模块正在退出\n");
    
    mutex_lock(&touch_dev.lock);
    
    if (touch_dev.input) {
        input_unregister_device(touch_dev.input);
        touch_dev.input = NULL;
        touch_dev.initialized = false;
        touch_dbg("[TearGame] 触控设备已注销\n");
    }
    
    mutex_unlock(&touch_dev.lock);
    
    tear_info("触控模块已清理\n");
}

/*
 * 使用屏幕尺寸初始化触控设备
 */
int teargame_touch_init_device(int width, int height)
{
    struct input_dev *input;
    int max_dim;
    int ret;
    int i;
    
    touch_dbg("[TearGame] 正在初始化触控设备 %dx%d\n", width, height);
    
    /* 使用较大尺寸作为最大值以支持旋转 */
    max_dim = (width > height) ? width : height;
    if (max_dim <= 0)
        max_dim = TEAR_TOUCH_DEFAULT_WIDTH;
    
    mutex_lock(&touch_dev.lock);
    
    /* 检查是否已初始化 */
    if (touch_dev.initialized && touch_dev.input) {
        touch_dbg("[TearGame] 触控设备已初始化\n");
        mutex_unlock(&touch_dev.lock);
        return 0;
    }
    
    /* 清理任何部分状态 */
    if (touch_dev.input) {
        touch_dbg("[TearGame] 正在清理之前的设备\n");
        input_unregister_device(touch_dev.input);
        touch_dev.input = NULL;
        touch_dev.initialized = false;
    }
    
    /* 分配输入设备 */
    input = input_allocate_device();
    if (!input) {
        touch_dbg("[TearGame] 分配输入设备失败\n");
        mutex_unlock(&touch_dev.lock);
        return -ENOMEM;
    }
    
    /* 设置设备信息 */
    input->name = TEAR_TOUCH_DEVICE_NAME;
    input->id.bustype = BUS_VIRTUAL;
    input->id.vendor = 0x0001;
    input->id.product = 0x0001;
    input->id.version = 0x0100;
    
    touch_dbg("[TearGame] 设备名称: %s\n", input->name);
    
    /* 设置能力 */
    __set_bit(EV_SYN, input->evbit);
    __set_bit(EV_ABS, input->evbit);
    __set_bit(EV_KEY, input->evbit);
    
    __set_bit(BTN_TOUCH, input->keybit);
    __set_bit(BTN_TOOL_FINGER, input->keybit);
    
    __set_bit(INPUT_PROP_DIRECT, input->propbit);
    
    /* 设置绝对轴 */
    input_set_abs_params(input, ABS_X, 0, max_dim, 0, 0);
    input_set_abs_params(input, ABS_Y, 0, max_dim, 0, 0);
    
    /* 多点触控轴 */
    input_set_abs_params(input, ABS_MT_POSITION_X, 0, max_dim, 0, 0);
    input_set_abs_params(input, ABS_MT_POSITION_Y, 0, max_dim, 0, 0);
    input_set_abs_params(input, ABS_MT_SLOT, 0, TEAR_TOUCH_MAX_SLOTS - 1, 0, 0);
    input_set_abs_params(input, ABS_MT_TRACKING_ID, 0, 
                         TEAR_TOUCH_MAX_SLOTS - 1, 0, 0);
    input_set_abs_params(input, ABS_MT_PRESSURE, 
                         TEAR_TOUCH_MIN_PRESSURE, 
                         TEAR_TOUCH_MAX_PRESSURE, 0, 0);
    input_set_abs_params(input, ABS_MT_TOUCH_MAJOR,
                         TEAR_TOUCH_MIN_MAJOR,
                         TEAR_TOUCH_MAX_MAJOR, 0, 0);
    
    /* 初始化多点触控槽位 */
    ret = input_mt_init_slots(input, TEAR_TOUCH_MAX_SLOTS, TEAR_MT_FLAGS);
    if (ret < 0) {
        touch_dbg("[TearGame] 初始化MT槽位失败: %d\n", ret);
        input_free_device(input);
        mutex_unlock(&touch_dev.lock);
        return ret;
    }
    
    touch_dbg("[TearGame] 已初始化 %d 个MT槽位\n", TEAR_TOUCH_MAX_SLOTS);
    
    /* 注册设备 */
    ret = input_register_device(input);
    if (ret < 0) {
        touch_dbg("[TearGame] 注册设备失败: %d\n", ret);
        input_free_device(input);
        mutex_unlock(&touch_dev.lock);
        return ret;
    }
    
    touch_dbg("[TearGame] 设备注册成功\n");
    
    /* 重置槽位状态 */
    for (i = 0; i < TEAR_TOUCH_MAX_SLOTS; i++) {
        touch_dev.slots[i].down = false;
        touch_dev.slots[i].x = 0;
        touch_dev.slots[i].y = 0;
    }
    
    touch_dev.input = input;
    touch_dev.width = max_dim;
    touch_dev.height = max_dim;
    touch_dev.initialized = true;
    
    mutex_unlock(&touch_dev.lock);
    
    tear_info("触控设备初始化完成 %dx%d\n", max_dim, max_dim);
    
    return 0;
}

/*
 * 发送触控按下事件
 */
int teargame_touch_down(int slot, int x, int y)
{
    struct input_dev *input;
    unsigned long flags;
    
    if (!touch_is_ready()) {
        touch_dbg("[TearGame] 触控按下失败 - 设备未就绪\n");
        return -ENODEV;
    }
    
    if (slot < 0 || slot >= TEAR_TOUCH_MAX_SLOTS) {
        touch_dbg("[TearGame] 无效槽位: %d\n", slot);
        return -EINVAL;
    }
    
    if (x < 0 || y < 0) {
        touch_dbg("[TearGame] 无效坐标: %d, %d\n", x, y);
        return -EINVAL;
    }
    
    atomic_inc(&touch_dev.total_down);
    
    /* 尝试先获取读锁以提高并发性 */
    if (!read_trylock(&touch_dev.rwlock)) {
        touch_dbg("[TearGame] 触控按下等待锁\n");
        mutex_lock(&touch_dev.lock);
        
        if (!touch_is_ready()) {
            mutex_unlock(&touch_dev.lock);
            return -ENODEV;
        }
        
        input = touch_dev.input;
        
        touch_dbg("[TearGame] 触控按下 slot=%d x=%d y=%d\n", slot, x, y);
        
        input_mt_slot(input, slot);
        input_mt_report_slot_state(input, MT_TOOL_FINGER, true);
        input_report_abs(input, ABS_MT_POSITION_X, x);
        input_report_abs(input, ABS_MT_POSITION_Y, y);
        input_report_abs(input, ABS_MT_PRESSURE, TEAR_TOUCH_DEFAULT_PRESSURE);
        input_report_abs(input, ABS_MT_TOUCH_MAJOR, TEAR_TOUCH_DEFAULT_MAJOR);
        
        input_mt_sync_frame(input);
        input_sync(input);
        
        touch_dev.slots[slot].down = true;
        touch_dev.slots[slot].x = x;
        touch_dev.slots[slot].y = y;
        touch_dev.slots[slot].down_time = tear_jiffies();
        
        mutex_unlock(&touch_dev.lock);
    } else {
        write_lock_irqsave(&touch_dev.rwlock, flags);
        
        input = touch_dev.input;
        if (!input) {
            write_unlock_irqrestore(&touch_dev.rwlock, flags);
            read_unlock(&touch_dev.rwlock);
            return -ENODEV;
        }
        
        touch_dbg("[TearGame] 触控按下 slot=%d x=%d y=%d\n", slot, x, y);
        
        input_mt_slot(input, slot);
        input_mt_report_slot_state(input, MT_TOOL_FINGER, true);
        input_report_abs(input, ABS_MT_POSITION_X, x);
        input_report_abs(input, ABS_MT_POSITION_Y, y);
        input_report_abs(input, ABS_MT_PRESSURE, TEAR_TOUCH_DEFAULT_PRESSURE);
        input_report_abs(input, ABS_MT_TOUCH_MAJOR, TEAR_TOUCH_DEFAULT_MAJOR);
        
        input_mt_sync_frame(input);
        input_sync(input);
        
        touch_dev.slots[slot].down = true;
        touch_dev.slots[slot].x = x;
        touch_dev.slots[slot].y = y;
        touch_dev.slots[slot].down_time = tear_jiffies();
        
        write_unlock_irqrestore(&touch_dev.rwlock, flags);
        read_unlock(&touch_dev.rwlock);
    }
    
    touch_dbg("[TearGame] 触控按下完成 槽位 %d\n", slot);
    return 0;
}

/*
 * 发送触控移动事件
 */
int teargame_touch_move(int slot, int x, int y)
{
    struct input_dev *input;
    unsigned long flags;
    
    if (!touch_is_ready()) {
        touch_dbg("[TearGame] 触控移动失败 - 设备未就绪\n");
        return -ENODEV;
    }
    
    if (slot < 0 || slot >= TEAR_TOUCH_MAX_SLOTS) {
        touch_dbg("[TearGame] 移动无效槽位: %d\n", slot);
        return -EINVAL;
    }
    
    /* 使用互斥锁简化加锁 */
    if (!mutex_trylock(&touch_dev.lock)) {
        mutex_lock(&touch_dev.lock);
    }
    
    if (!touch_is_ready()) {
        mutex_unlock(&touch_dev.lock);
        return -ENODEV;
    }
    
    input = touch_dev.input;
    
    touch_dbg("[TearGame] 触控移动 slot=%d x=%d y=%d\n", slot, x, y);
    
    write_lock_irqsave(&touch_dev.rwlock, flags);
    
    input_mt_slot(input, slot);
    input_report_abs(input, ABS_MT_POSITION_X, x);
    input_report_abs(input, ABS_MT_POSITION_Y, y);
    
    input_mt_sync_frame(input);
    input_sync(input);
    
    touch_dev.slots[slot].x = x;
    touch_dev.slots[slot].y = y;
    
    write_unlock_irqrestore(&touch_dev.rwlock, flags);
    mutex_unlock(&touch_dev.lock);
    
    return 0;
}

/*
 * 发送触控抬起事件
 */
int teargame_touch_up(int slot)
{
    struct input_dev *input;
    unsigned long flags;
    
    if (!touch_is_ready()) {
        touch_dbg("[TearGame] 触控抬起失败 - 设备未就绪\n");
        return -ENODEV;
    }
    
    if (slot < 0 || slot >= TEAR_TOUCH_MAX_SLOTS) {
        touch_dbg("[TearGame] 抬起无效槽位: %d\n", slot);
        return -EINVAL;
    }
    
    /* 检查槽位是否实际按下 */
    if (!touch_dev.slots[slot].down) {
        touch_dbg("[TearGame] 槽位 %d 未按下，忽略抬起\n", slot);
        return 0;
    }
    
    atomic_inc(&touch_dev.total_up);
    
    if (!mutex_trylock(&touch_dev.lock)) {
        touch_dbg("[TearGame] 触控抬起等待锁\n");
        mutex_lock(&touch_dev.lock);
    }
    
    if (!touch_is_ready()) {
        mutex_unlock(&touch_dev.lock);
        return -ENODEV;
    }
    
    /* 在锁下双重检查槽位状态 */
    if (!touch_dev.slots[slot].down) {
        mutex_unlock(&touch_dev.lock);
        return 0;
    }
    
    input = touch_dev.input;
    
    touch_dbg("[TearGame] 触控抬起 slot=%d\n", slot);
    
    write_lock_irqsave(&touch_dev.rwlock, flags);
    
    input_mt_slot(input, slot);
    input_mt_report_slot_state(input, MT_TOOL_FINGER, false);
    input_sync(input);
    
    touch_dev.slots[slot].down = false;
    
    write_unlock_irqrestore(&touch_dev.rwlock, flags);
    mutex_unlock(&touch_dev.lock);
    
    touch_dbg("[TearGame] 触控抬起完成 槽位 %d\n", slot);
    return 0;
}

/*
 * 设置调试模式
 */
void teargame_touch_set_debug(int enable)
{
    touch_dev.debug = (enable != 0);
    tear_info("触控调试模式 %s\n", touch_dev.debug ? "已启用" : "已禁用");
}
