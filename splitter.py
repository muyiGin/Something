def hex_2_bin(hex_str):
    return bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)


def bin_2_hex(bin_str):
    return hex(int(bin_str, 2))[2:].zfill(len(bin_str) // 4)


def format_hex(hex_input: str):
    hex_str = hex_input.strip()
    hex_str = hex_str.replace("`", "").replace(" ", "")
    return hex_str


def explain_selector(bin_str):
    index = int(bin_str[0:13], 2)
    ti = bin_str[13]
    rpl = int(bin_str[14:16], 2)

    table = "GDT" if ti == "0" else "LDT"
    ring = f"ring{rpl}"

    print(f"段选择子在{table}表,权限级别{ring},索引是{index}")


def explain_type(type_bits: str):
    type_dict = {
        # 数据段类型
        "0000": "Data段，只读",
        "0001": "Data段，只读，已访问",
        "0010": "Data段，可读可写",
        "0011": "Data段，可读可写，已访问",
        "0100": "Data段，只读，向下扩展",
        "0101": "Data段，只读，向下扩展，已访问",
        "0110": "Data段，可读可写，向下扩展",
        "0111": "Data段，可读可写，向下扩展，已访问",
        # 代码段类型
        "1000": "Code段，只执行",
        "1001": "Code段，只执行，已访问",
        "1010": "Code段，可执行可读",
        "1011": "Code段，可执行可读，已访问",
        "1100": "Code段，只执行，从外部调用",
        "1101": "Code段，只执行，从外部调用，已访问",
        "1110": "Code段，可执行可读，从外部调用",
        "1111": "Code段，可执行可读，从外部调用，已访问",
    }

    result = type_dict.get(type_bits)
    if result:
        print("段类型：", result)
    else:
        print("未知的Type值：", type_bits)


def seg_description(bin_str):
    bin_str = bin_str[::-1]
    bs1 = bin_str[0:32]
    bs2 = bin_str[32:64]
    limit_1 = bs1[0:16][::-1]
    base_1 = bs1[16:32][::-1]
    base_2 = bs2[0:8][::-1]
    Type = bs2[8:12][::-1]
    S = bs2[12:13][::-1]
    DPL = bs2[13:15][::-1]
    P = bs2[15:16][::-1]
    limit_2 = bs2[16:20][::-1]
    AVL = bs2[20:21][::-1]
    DB = bs2[22:23][::-1]
    G = bs2[23:24][::-1]
    base_3 = bs2[24:32][::-1]
    print("段描述符是否有效：", P == "1")
    print("DPL权限是：", "ring3" if bin_2_hex(DPL) == "3" else "ring0")
    print("Base地址是：", bin_2_hex(base_3 + base_2 + base_1))
    print("Limit大小是：", bin_2_hex(limit_2 + limit_1))
    print("颗粒度是：", "4k" if G == "1" else "bytes")
    print("S标志位代表的是：", "用户段" if S == "1" else "系统段")
    explain_type(Type)
    print("DPL代表几位模式：", "32位" if DB == "1" else "16位")
    print("AVL是：", AVL)


def call_gate(bin_str):
    bin_str = bin_str[::-1]
    bs1 = bin_str[0:32]
    bs2 = bin_str[32:64]
    offset_1 = bs1[0:16][::-1]
    selector = bs1[16:32][::-1]
    param = bs2[0:5][::-1]
    Type = bs2[8:12][::-1]
    DPL = bs2[13:15][::-1]
    P = bs2[15:16][::-1]
    offset_2 = bs2[16:32][::-1]
    print("段描述符是否有效：", P == "1")
    print("DPL权限是：", "ring3" if bin_2_hex(DPL) == "3" else "ring0")
    explain_selector(selector)
    print("参数数量是：", bin_2_hex(param))
    print("段中偏移是：", bin_2_hex(offset_2 + offset_1))
    print("调用门的类型应该是1100：", Type)


def trap_gate(bin_str):
    bin_str = bin_str[::-1]
    bs1 = bin_str[0:32]
    bs2 = bin_str[32:64]
    offset_1 = bs1[0:16][::-1]
    selector = bs1[16:32][::-1]
    Type = bs2[8:12][::-1]
    DPL = bs2[13:15][::-1]
    P = bs2[15:16][::-1]
    offset_2 = bs2[16:32][::-1]
    print("段描述符是否有效：", P == "1")
    print("DPL权限是：", "ring3" if bin_2_hex(DPL) == "3" else "ring0")
    explain_selector(selector)
    print("段中偏移是：", bin_2_hex(offset_2 + offset_1))
    print("陷阱门的类型应该是1111：", Type)


def make_call_gate(selector_index: str, offset: str, param_count: str):
    # 选择子编号是十进制
    selector_index = int(selector_index)
    # 偏移是十六进制（带前导0也可以）
    offset = int(offset, 16)
    # 参数数量是十进制
    param_count = int(param_count)
    selector = selector_index << 3  # GDT 每项 8 字节
    offset_low = offset & 0xFFFF
    offset_high = (offset >> 16) & 0xFFFF
    param = param_count & 0b11111
    reserved = 0
    Type = 0xC
    S = 0
    DPL = 0b11
    P = 1
    low_dword = offset_low | (selector << 16)
    high_dword = (param & 0x1F) | (reserved << 5) | (Type << 8) | (S << 12) | (DPL << 13) | (P << 15) | (offset_high << 16)
    full_gate = (high_dword << 32) | low_dword
    print(f"调用门是：{full_gate:016X}")
    return


def make_selector(index: str, ti: int = 0, rpl: int = 3) -> str:
    index = int(index, 10)
    selector = (index << 3) | (ti << 2) | rpl
    print(f"段选择子是：{selector:04X}")
    return


def make_trap_gate(selector_index: str, offset: str, dpl: str = "3"):
    """
    selector_index: 选择子编号（十进制字符串）
    offset: 目标偏移地址（十六进制字符串）
    dpl: Descriptor Privilege Level（默认为3，可设为0）
    """
    selector_index = int(selector_index)
    offset = int(offset, 16)
    dpl = int(dpl)

    selector = selector_index << 3
    offset_low = offset & 0xFFFF
    offset_high = (offset >> 16) & 0xFFFF

    # 陷阱门的Type为0xF
    Type = 0xF
    S = 0
    P = 1

    # 构造低32位
    low_dword = offset_low | (selector << 16)

    # 构造高32位（param/保留位省略）
    high_dword = (Type << 8) | (S << 12) | (dpl << 13) | (P << 15) | (offset_high << 16)

    # 合并为64位
    full_gate = (high_dword << 32) | low_dword
    print(f"陷阱门是：{full_gate:016X}")
    return


while True:
    print("=======================================")
    option = input("1.拆分    2.制作：")
    if option == "1":
        input_str = input("请输入你想拆分的对象：")
        hex_str = format_hex(input_str)
        bin_str = hex_2_bin(hex_str)
        input_type = input("请输入其类型：1.段描述符，2.调用门，3.陷阱门，4.段选择子\n")
        if input_type == "1":
            print("你正在拆分一个段描述符...\n")
            seg_description(bin_str)
        elif input_type == "2":
            print("你正在拆分一个调用门...\n")
            call_gate(bin_str)
        elif input_type == "3":
            print("你正在拆分一个陷阱门...\n")
            trap_gate(bin_str)
        elif input_type == "4":
            print("你正在拆分一个段选择子...\n")
            explain_selector(bin_str)
    elif option == "2":
        input_type = input("请输入制作的对象：1.段描述符，2.调用门，3.陷阱门，4.段选择子\n")
        if input_type == "2":
            selector_index = input("请输入选择子的编号：")
            offset = input("请输入调用门的执行函数偏移：")
            param_count = input("请输入函数参数的个数：")
            make_call_gate(selector_index, offset, param_count)
        elif input_type == "3":
            selector_index = input("请输入选择子的编号：")
            offset = input("请输入调用门的执行函数偏移：")
            make_trap_gate(selector_index, offset)

        elif input_type == "4":
            selector_index = input("请输入选择子的编号：")
            make_selector(selector_index)

    else:
        print("输入错误！")
