from tkinter.tix import InputOnly


def hex_2_bin(hex_str):
    return bin(int(hex_str, 16))[2:].zfill(32)


while True:
    print("======================================================")
    option = input("1.制作 2.拆分：")
    if option == "1":
        input_type = input("请输入你想制作的类型（1.PDE 2.PTE）：")
        if input_type == "2":
            # P=1，G=0，PWT/PCD默认
            RW = input("0是只读，1是可写：")
            US = input("0是特权用户，1是用户态：")
            PS = input("是否直接指向物理页（是的话选1）：")
            if PS == "1":
                offset = input("低22位就是页内偏移（16进制）：")
                try:
                    addr = int(offset, 16)
                    page_frame = addr & 0xFFFFF000  # 页框基地址（20位）
                except ValueError:
                    print("地址格式错误")
                    continue
            else:
                page_frame = int(input("请输入你想指向的物理页地址（必须是4KB对齐）："), 16) & 0xFFFFF000

            A = input("是否被访问过（是1，否0）：")
            D = input("是否被修改过（是1，否0）：")
            G = input("是否为global页（是1，否0）：")

            # 构造 PTE
            pte = 0
            pte |= 1  # Present = 1
            pte |= int(RW) << 1
            pte |= int(US) << 2
            pte |= 0 << 3  # PWT默认0
            pte |= 0 << 4  # PCD默认0
            pte |= int(A) << 5
            pte |= int(D) << 6
            pte |= int(PS) << 7  # 用作 PAT/页大小标记
            pte |= int(G) << 8
            pte |= page_frame  # 高位地址部分

            print(f"你构造的PTE是：0x{pte:08X}")

    elif option == "2":
        input_type = input("1.将虚拟地址转为物理地址 2.拆解PTE：")
        if input_type == "1":
            source = input("请输入想要转为物理地址的虚拟地址：")
            mode = input("10-10-12模式选0，2-9-9-12模式选1：")
            bin_str = hex_2_bin(source)
            cr3 = int(input("请输入你搜到的cr3："), 16)

            if mode == "0":
                PDE = int(bin_str[0:10], 2)  # 高10位
                PTE = int(bin_str[10:20], 2)  # 中10位
                offset = int(bin_str[20:32], 2)  # 低12位
                pde = int(input(f"pde的地址是{cr3+PDE*4:X},请输入你查到的pde："), 16)
                pte = int(input(f"pte地址是{(pde&0xFFFFF000)+PTE*4:X},请输入你查到的pte："), 16)
                real_addr = (pte & 0xFFFFF000) + offset
                print(f"物理地址是：0x{real_addr:X}")
        elif input_type == "2":
            pte_hex = input("请输入你想拆解的PTE（16进制）：")
            try:
                pte = int(pte_hex, 16)
            except ValueError:
                print("输入格式错误，请输入16进制数")
                continue

            print("=== PTE 拆解结果 ===")
            # Present
            present = (pte >> 0) & 1
            print(f"P  (Present)             ：{'存在' if present else '不存在'}")

            # Read/Write
            rw = (pte >> 1) & 1
            print(f"RW (Read/Write)          ：{'可读可写' if rw else '只读'}")

            # User/Supervisor
            us = (pte >> 2) & 1
            print(f"US (User/Supervisor)     ：{'用户态' if us else '特权态'}")

            # Write-Through
            pwt = (pte >> 3) & 1
            print(f"PWT (Write-Through)      ：{'启用' if pwt else '未启用'}")

            # Cache Disable
            pcd = (pte >> 4) & 1
            print(f"PCD (Cache Disable)      ：{'禁用' if pcd else '启用'}")

            # Accessed
            accessed = (pte >> 5) & 1
            print(f"A  (Accessed)            ：{'已访问' if accessed else '未访问'}")

            # Dirty
            dirty = (pte >> 6) & 1
            print(f"D  (Dirty)               ：{'已修改' if dirty else '未修改'}")

            # PAT (Page Attribute Table)
            pat = (pte >> 7) & 1
            print(f"PAT                      ：{'启用' if pat else '未启用'}")

            # Global
            global_page = (pte >> 8) & 1
            print(f"G  (Global)              ：{'全局页' if global_page else '局部页'}")

            # OS Available Bits
            avl = (pte >> 9) & 0b111
            print(f"AVL (OS Available Bits)  ：{avl:03b}")

            # PS (Page Size, whether it points to a 4KB or larger page)
            ps = (pte >> 7) & 1  # PS 位用于区分页大小，大页的话PS=1
            print(f"PS (Page Size)          ：{'大页' if ps else '小页'}")

            # 物理页框地址
            page_frame = (pte >> 12) & 0xFFFFF
            print(f"页框地址（物理页基址）  ：0x{page_frame << 12:08X}")
