import hashlib
from typing import Optional, Tuple

try:
    from PIL import Image
    IMAGE_SUPPORT = True
except ImportError:
    IMAGE_SUPPORT = False


class TextCipher:
    IMAGE_MARKER = b'<<TCIMG>>'

    def __init__(self, passphrase: str):
        if not passphrase:
            raise ValueError("密码短语不能为空")
        self.passphrase = passphrase
        # 从密码短语生成固定长度的密钥 (32 字节)
        self.key = hashlib.sha256(passphrase.encode('utf-8')).digest()

    def _generate_key_stream(self, length: int) -> bytes:
        """生成密钥流，用于异或操作"""
        key_stream = b''
        while len(key_stream) < length:
            key_stream += self.key
        return key_stream[:length]

    def encrypt(self, plaintext: str) -> str:
        if not plaintext:
            return ""

        # 将文本转换为字节
        plaintext_bytes = plaintext.encode('utf-8')

        # 生成密钥流
        key_stream = self._generate_key_stream(len(plaintext_bytes))

        # 异或加密
        encrypted_bytes = bytes(a ^ b for a, b in zip(plaintext_bytes, key_stream))

        # 添加校验和 (SHA256 的前 4 字节)
        checksum = hashlib.sha256(plaintext_bytes).digest()[:4]
        encrypted_with_checksum = encrypted_bytes + checksum

        # 转换为十六进制字符串
        return encrypted_with_checksum.hex().upper()

    def decrypt(self, ciphertext: str) -> Optional[str]:
        if not ciphertext:
            return ""

        try:
            # 从十六进制转换回字节
            encrypted_with_checksum = bytes.fromhex(ciphertext.upper())

            if len(encrypted_with_checksum) < 4:
                return None

            # 分离数据和校验和
            encrypted_bytes = encrypted_with_checksum[:-4]
            checksum = encrypted_with_checksum[-4:]

            # 生成密钥流
            key_stream = self._generate_key_stream(len(encrypted_bytes))

            # 异或解密
            decrypted_bytes = bytes(a ^ b for a, b in zip(encrypted_bytes, key_stream))

            # 验证校验和
            expected_checksum = hashlib.sha256(decrypted_bytes).digest()[:4]
            if checksum != expected_checksum:
                return None  # 校验失败，密钥可能错误

            # 转换为字符串
            return decrypted_bytes.decode('utf-8')
        except Exception:
            return None

    @staticmethod
    def _text_to_bits(text: str) -> list:
        """将文本转换为比特列表"""
        bits = []
        for byte in text.encode('utf-8'):
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits
    @staticmethod
    def _bits_to_text(bits: list) -> str:
        """将比特列表转换为文本"""
        bytes_list = []
        for i in range(0, len(bits), 8):
            byte_bits = bits[i:i+8]
            if len(byte_bits) == 8:
                byte_val = 0
                for bit in byte_bits:
                    byte_val = (byte_val << 1) | bit
                bytes_list.append(byte_val)
        return bytes(bytes_list).decode('utf-8', errors='ignore')

    def encrypt_to_image(self, plaintext: str, image_path: str, output_path: str) -> Tuple[bool, str]:
        if not IMAGE_SUPPORT:
            return False, "未安装 Pillow 库，请运行：pip install Pillow"

        try:
            # 先加密文本
            ciphertext = self.encrypt(plaintext)
            if not ciphertext:
                return False, "加密失败"

            # 添加标记和数据长度信息
            marker_bytes = self.IMAGE_MARKER
            length_bytes = len(ciphertext).to_bytes(4, 'big')
            cipher_bytes = ciphertext.encode('utf-8')
            data_bytes = marker_bytes + length_bytes + cipher_bytes

            # 转换为比特列表
            bits = []
            for byte in data_bytes:
                for i in range(7, -1, -1):
                    bits.append((byte >> i) & 1)

            # 打开图像
            img = Image.open(image_path)

            # 检查图像模式，转换为 RGB
            if img.mode != 'RGB':
                img = img.convert('RGB')

            # 检查图像容量是否足够
            max_bits = img.width * img.height * 3
            if len(bits) > max_bits:
                return False, f"图像容量不足，需要 {len(bits)} bits，可用 {max_bits} bits"

            # 获取像素
            pixels = img.load()
            bit_idx = 0
            for y in range(img.height):
                for x in range(img.width):
                    if bit_idx >= len(bits):
                        break

                    pixel = list(pixels[x, y])

                    # 修改 R 通道
                    if bit_idx < len(bits):
                        pixel[0] = (pixel[0] & 0xFE) | bits[bit_idx]
                        bit_idx += 1

                    # 修改 G 通道
                    if bit_idx < len(bits):
                        pixel[1] = (pixel[1] & 0xFE) | bits[bit_idx]
                        bit_idx += 1

                    # 修改 B 通道
                    if bit_idx < len(bits):
                        pixel[2] = (pixel[2] & 0xFE) | bits[bit_idx]
                        bit_idx += 1

                    pixels[x, y] = tuple(pixel)

                if bit_idx >= len(bits):
                    break

            # 保存图像为 PNG 格式 (无损压缩)
            img.save(output_path, 'PNG')
            return True, f"成功将 {len(plaintext)} 字符加密到图像 ({img.width}x{img.height})"

        except FileNotFoundError:
            return False, f"图像文件不存在：{image_path}"
        except Exception as e:
            return False, f"图像加密失败：{str(e)}"

        def decrypt_from_image(self, image_path: str) -> Tuple[Optional[str], Optional[str]]:

            if not IMAGE_SUPPORT:
                return None, "NO_IMAGE_SUPPORT: 未安装 Pillow 库，请运行 pip install Pillow"

        try:
            # 打开图像
            img = Image.open(image_path)
            original_format = img.format
            if img.mode != 'RGB':
                img = img.convert('RGB')

            # 检查图片格式
            if original_format and original_format.upper() == 'JPEG':
                return None, "FORMAT_ERROR: 图片为 JPEG 格式，JPG 压缩会破坏 LSB 隐写数据，请使用原始 PNG 图片"

            # 提取所有 LSB 数据
            pixels = img.load()
            bits = []

            for y in range(img.height):
                for x in range(img.width):
                    pixel = pixels[x, y]
                    bits.append(pixel[0] & 1)  # R 通道 LSB
                    bits.append(pixel[1] & 1)  # G 通道 LSB
                    bits.append(pixel[2] & 1)  # B 通道 LSB

            # 转换为文本
            extracted_data = self._bits_to_text(bits)

            # 查找标记
            marker_pos = extracted_data.find(self.IMAGE_MARKER.decode('utf-8'))
            if marker_pos == -1:
                return None, "NO_MARKER: 图片不包含加密数据标记，可能原因:\n1. 此图片未经本工具加密\n2. 图片被压缩或修改过 (如 JPG 压缩会破坏 LSB 数据)\n3. 图片格式不支持"

            # 读取数据长度
            data_start = marker_pos + len(self.IMAGE_MARKER)
            length_bytes = extracted_data[data_start:data_start+4].encode('utf-8')
            if len(length_bytes) < 4:
                return None, "DATA_INCOMPLETE: 数据长度信息不完整，图片可能被截断或修改"

            # 由于 UTF-8 编码问题，需要重新处理
            # 我们从 bits 直接提取字节数据
            data_bits = bits
            data_bytes = []
            # 根据图片大小动态调整读取范围
            max_bytes = min(len(data_bits) // 8, img.width * img.height * 3 // 8)
            for i in range(0, max_bytes * 8, 8):
                byte_bits = data_bits[i:i+8]
                if len(byte_bits) == 8:
                    byte_val = 0
                    for bit in byte_bits:
                        byte_val = (byte_val << 1) | bit
                    data_bytes.append(byte_val)

            data_bytes = bytes(data_bytes)

            # 查找标记
            marker_idx = data_bytes.find(self.IMAGE_MARKER)
            if marker_idx == -1:
                return None, "NO_MARKER: 图片不包含有效的加密数据标记"

            # 读取长度
            length_start = marker_idx + len(self.IMAGE_MARKER)
            if length_start + 4 > len(data_bytes):
                return None, "DATA_INCOMPLETE: 数据长度信息超出范围"

            data_length = int.from_bytes(data_bytes[length_start:length_start+4], 'big')

            # 读取密文
            cipher_start = length_start + 4
            cipher_end = cipher_start + data_length
            if cipher_end > len(data_bytes):
                return None, "DATA_INCOMPLETE: 密文数据不完整，图片容量可能不足或被修改"

            ciphertext = data_bytes[cipher_start:cipher_end].decode('utf-8', errors='ignore')

            # 解密密文
            result = self.decrypt(ciphertext)
            if result is None:
                return None, "DECRYPT_FAILED: 密码短语错误或数据已损坏"
            return result, None

        except FileNotFoundError:
            return None, "FILE_NOT_FOUND: 图片文件不存在"
        except Exception as e:
            return None, f"UNKNOWN_ERROR: {str(e)}"

    def split_encrypt_to_images(self, plaintext: str, image_path: str, output_dir: str, split_count: int = 2) -> Tuple[bool, str]:

        if not IMAGE_SUPPORT:
            return False, "未安装 Pillow 库，请运行：pip install Pillow"

        if split_count < 1 or split_count > 5:
            return False, "拆分数量必须在 1-5 之间"

        if split_count == 1:
            # 如果只有1个，直接使用普通加密
            import os
            output_path = os.path.join(output_dir, "hidden_1.png")
            return self.encrypt_to_image(plaintext, image_path, output_path)

        try:
            import os

            # 先加密文本
            ciphertext = self.encrypt(plaintext)
            if not ciphertext:
                return False, "加密失败"

            # 添加标记和数据长度信息
            marker_bytes = self.IMAGE_MARKER
            length_bytes = len(ciphertext).to_bytes(4, 'big')
            cipher_bytes = ciphertext.encode('utf-8')
            data_bytes = marker_bytes + length_bytes + cipher_bytes

            # 添加拆分信息头: SPLIT<N>
            split_header = f"SPLIT{split_count}".encode('utf-8')
            data_with_header = split_header + data_bytes

            # 转换为比特列表
            bits = []
            for byte in data_with_header:
                for i in range(7, -1, -1):
                    bits.append((byte >> i) & 1)

            # 将比特分散到N个图片
            # 策略: 第i位比特存入第 (i % N) 个图片
            bits_per_image = [[] for _ in range(split_count)]
            for i, bit in enumerate(bits):
                bits_per_image[i % split_count].append(bit)

            # 打开模板图像
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')

            # 确保输出目录存在
            os.makedirs(output_dir, exist_ok=True)

            output_files = []
            for img_idx in range(split_count):
                # 复制原图像
                new_img = img.copy()
                pixels = new_img.load()

                # 将该图片的比特嵌入
                img_bits = bits_per_image[img_idx]
                bit_idx = 0

                for y in range(new_img.height):
                    for x in range(new_img.width):
                        if bit_idx >= len(img_bits):
                            break

                        pixel = list(pixels[x, y])

                        # 只修改 R 通道 (每个像素存1位)
                        pixel[0] = (pixel[0] & 0xFE) | img_bits[bit_idx]
                        bit_idx += 1

                        pixels[x, y] = tuple(pixel)

                    if bit_idx >= len(img_bits):
                        break

                # 保存图片
                output_path = os.path.join(output_dir, f"hidden_{img_idx + 1}.png")
                new_img.save(output_path, 'PNG')
                output_files.append(output_path)

            return True, f"成功将 {len(plaintext)} 字符拆分加密到 {split_count} 个图片\n输出文件: {', '.join(output_files)}"

        except FileNotFoundError:
            return False, f"图像文件不存在：{image_path}"
        except Exception as e:
            return False, f"拆分加密失败：{str(e)}"

    def merge_decrypt_from_images(self, image_paths: list) -> Tuple[Optional[str], Optional[str]]:

        if not IMAGE_SUPPORT:
            return None, "NO_IMAGE_SUPPORT: 未安装 Pillow 库，请运行 pip install Pillow"

        if not image_paths or len(image_paths) == 0:
            return None, "NO_IMAGES: 未提供图片"

        try:
            split_count = len(image_paths)

            # 从每个图片提取比特
            all_bits = []
            bits_from_images = []

            for img_path in image_paths:
                img = Image.open(img_path)
                if img.mode != 'RGB':
                    img = img.convert('RGB')

                pixels = img.load()
                bits = []

                for y in range(img.height):
                    for x in range(img.width):
                        pixel = pixels[x, y]
                        bits.append(pixel[0] & 1)  # 只读 R 通道

                bits_from_images.append(bits)

            # 合并比特 (第i位来自第 (i % N) 个图片)
            max_bits = max(len(b) for b in bits_from_images)
            merged_bits = []

            for i in range(max_bits):
                img_idx = i % split_count
                bit_idx = i // split_count
                if bit_idx < len(bits_from_images[img_idx]):
                    merged_bits.append(bits_from_images[img_idx][bit_idx])

            # 转换为字节
            data_bytes = []
            for i in range(0, len(merged_bits), 8):
                byte_bits = merged_bits[i:i+8]
                if len(byte_bits) == 8:
                    byte_val = 0
                    for bit in byte_bits:
                        byte_val = (byte_val << 1) | bit
                    data_bytes.append(byte_val)

            data_bytes = bytes(data_bytes)

            # 检查拆分头
            if data_bytes[:5] == b"SPLIT":
                # 解析拆分数量
                split_header = data_bytes[:6].decode('utf-8')  # SPLIT1-5
                expected_count = int(split_header[5])
                if expected_count != split_count:
                    return None, f"SPLIT_MISMATCH: 需要提供 {expected_count} 个图片，但只提供了 {split_count} 个"
                data_start = 6
            else:
                # 兼容非拆分格式
                data_start = 0

            # 查找标记
            marker_idx = data_bytes.find(self.IMAGE_MARKER, data_start)
            if marker_idx == -1:
                return None, "NO_MARKER: 未找到加密数据标记，请检查:\n1. 图片顺序是否正确\n2. 图片是否被修改"

            # 读取长度
            length_start = marker_idx + len(self.IMAGE_MARKER)
            if length_start + 4 > len(data_bytes):
                return None, "DATA_INCOMPLETE: 数据长度信息不完整"

            data_length = int.from_bytes(data_bytes[length_start:length_start+4], 'big')

            # 读取密文
            cipher_start = length_start + 4
            cipher_end = cipher_start + data_length
            if cipher_end > len(data_bytes):
                return None, "DATA_INCOMPLETE: 密文数据不完整"

            ciphertext = data_bytes[cipher_start:cipher_end].decode('utf-8', errors='ignore')

            # 解密
            result = self.decrypt(ciphertext)
            if result is None:
                return None, "DECRYPT_FAILED: 密码短语错误或数据已损坏"
            return result, None

        except FileNotFoundError as e:
            return None, f"FILE_NOT_FOUND: 图片文件不存在 - {e}"
        except Exception as e:
            return None, f"UNKNOWN_ERROR: {str(e)}"


def encrypt_text(text: str, passphrase: str) -> str:
    cipher = TextCipher(passphrase)
    return cipher.encrypt(text)


def decrypt_text(ciphertext: str, passphrase: str) -> Optional[str]:
    cipher = TextCipher(passphrase)
    return cipher.decrypt(ciphertext)


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
            description='文本加密工具 - 支持文本加密/解密和图像隐写',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
        示例:
  # 文本加密
  python text_cipher.py encrypt -p "mypassword" -t "秘密信息"
  python text_cipher.py encrypt -p "mypassword" -f plaintext.txt

  # 文本解密
  python text_cipher.py decrypt -p "mypassword" -c "2D9259768C84..."
  python text_cipher.py decrypt -p "mypassword" -f ciphertext.txt

  # 图像加密 (将文本隐藏到图片)
  python text_cipher.py img-encrypt -p "mypassword" -t "秘密信息" -i photo.png -o hidden.png

  # 图像解密 (从图片提取文本)
  python text_cipher.py img-decrypt -p "mypassword" -i hidden.png

  # 拆分加密 (将文本分散到N个图片)
  python text_cipher.py img-split-encrypt -p "mypassword" -t "秘密信息" -i photo.png -d ./output -n 3

  # 合并解密 (从N个图片提取文本)
  python text_cipher.py img-merge-decrypt -p "mypassword" -i hidden_1.png hidden_2.png hidden_3.png

  # 测试模式
  python text_cipher.py test
  """
  )

    subparsers = parser.add_subparsers(dest='command', help='命令')

    # === encrypt 命令 ===
    enc_parser = subparsers.add_parser('encrypt', help='文本加密')
    enc_parser.add_argument('-p', '--passphrase', required=True, help='密码短语')
    enc_parser.add_argument('-t', '--text', help='要加密的明文')
    enc_parser.add_argument('-f', '--file', help='从文件读取明文')

    # === decrypt 命令 ===
    dec_parser = subparsers.add_parser('decrypt', help='文本解密')
    dec_parser.add_argument('-p', '--passphrase', required=True, help='密码短语')
    dec_parser.add_argument('-c', '--ciphertext', help='要解密的密文')
    dec_parser.add_argument('-f', '--file', help='从文件读取密文')

    # === img-encrypt 命令 ===
    img_enc_parser = subparsers.add_parser('img-encrypt', help='图像加密 (将文本隐藏到图片)')
    img_enc_parser.add_argument('-p', '--passphrase', required=True, help='密码短语')
    img_enc_parser.add_argument('-t', '--text', help='要隐藏的明文')
    img_enc_parser.add_argument('-f', '--file', help='从文件读取明文')
    img_enc_parser.add_argument('-i', '--image', required=True, help='输入图片路径 (PNG)')
    img_enc_parser.add_argument('-o', '--output', required=True, help='输出图片路径 (PNG)')

    # === img-decrypt 命令 ===
    img_dec_parser = subparsers.add_parser('img-decrypt', help='图像解密 (从图片提取文本)')
    img_dec_parser.add_argument('-p', '--passphrase', required=True, help='密码短语')
    img_dec_parser.add_argument('-i', '--image', required=True, help='包含隐藏数据的图片路径')

    # === img-split-encrypt 命令 ===
    img_split_enc = subparsers.add_parser('img-split-encrypt', help='拆分加密 (将文本分散到N个图片)')
    img_split_enc.add_argument('-p', '--passphrase', required=True, help='密码短语')
    img_split_enc.add_argument('-t', '--text', help='要隐藏的明文')
    img_split_enc.add_argument('-f', '--file', help='从文件读取明文')
    img_split_enc.add_argument('-i', '--image', required=True, help='输入图片模板路径 (PNG)')
    img_split_enc.add_argument('-d', '--output-dir', required=True, help='输出目录')
    img_split_enc.add_argument('-n', '--split-count', type=int, default=2, choices=range(1, 6),
                               help='拆分数量 (1-5, 默认2)')

    # === img-merge-decrypt 命令 ===
    img_merge_dec = subparsers.add_parser('img-merge-decrypt', help='合并解密 (从N个图片提取文本)')
    img_merge_dec.add_argument('-p', '--passphrase', required=True, help='密码短语')
    img_merge_dec.add_argument('-i', '--images', nargs='+', required=True,
                               help='包含隐藏数据的图片路径 (按顺序, 空格分隔)')

    # === test 命令 ===
    subparsers.add_parser('test', help='运行测试示例')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # 测试模式
    if args.command == 'test':
        test_text = "Hello, World! 你好，世界！"
        password = "my_secret_key"

        print(f"原文：{test_text}")
        print(f"密码：{password}")
        print()

        encrypted = encrypt_text(test_text, password)
        print(f"加密后：{encrypted}")
        print()

        decrypted = decrypt_text(encrypted, password)
        print(f"解密后：{decrypted}")
        print()

        if test_text == decrypted:
            print("✅ 加密/解密成功！")
        else:
            print("❌ 加密/解密失败！")
        sys.exit(0)

    # 文本加密
    if args.command == 'encrypt':
        if not args.text and not args.file:
            print("❌ 请使用 -t 指定明文或 -f 指定文件")
            sys.exit(1)

        plaintext = args.text if args.text else open(args.file, 'r').read()
        result = encrypt_text(plaintext, args.passphrase)
        print(result)
        sys.exit(0)

    # 文本解密
    if args.command == 'decrypt':
        if not args.ciphertext and not args.file:
            print("❌ 请使用 -c 指定密文或 -f 指定文件")
            sys.exit(1)

        ciphertext = args.ciphertext if args.ciphertext else open(args.file, 'r').read().strip()
        result = decrypt_text(ciphertext, args.passphrase)
        if result:
            print(result)
            sys.exit(0)
        else:
            print("❌ 解密失败！密码错误或密文格式不正确")
            sys.exit(1)

    # 图像加密
    if args.command == 'img-encrypt':
        if not args.text and not args.file:
            print("❌ 请使用 -t 指定明文或 -f 指定文件")
            sys.exit(1)

        plaintext = args.text if args.text else open(args.file, 'r').read()
        cipher = TextCipher(args.passphrase)
        success, message = cipher.encrypt_to_image(plaintext, args.image, args.output)
        if success:
            print(f"✅ {message}")
            print(f"输出文件: {args.output}")
            sys.exit(0)
        else:
            print(f"❌ {message}")
            sys.exit(1)

    # 图像解密
    if args.command == 'img-decrypt':
        cipher = TextCipher(args.passphrase)
        result, error = cipher.decrypt_from_image(args.image)
        if result:
            print(result)
            sys.exit(0)
        else:
            print(f"❌ {error}")
            sys.exit(1)

    # 拆分加密
    if args.command == 'img-split-encrypt':
        if not args.text and not args.file:
            print("❌ 请使用 -t 指定明文或 -f 指定文件")
            sys.exit(1)

        plaintext = args.text if args.text else open(args.file, 'r').read()
        cipher = TextCipher(args.passphrase)
        success, message = cipher.split_encrypt_to_images(plaintext, args.image, args.output_dir, args.split_count)
        if success:
            print(f"✅ {message}")
            sys.exit(0)
        else:
            print(f"❌ {message}")
            sys.exit(1)

    # 合并解密
    if args.command == 'img-merge-decrypt':
        cipher = TextCipher(args.passphrase)
        result, error = cipher.merge_decrypt_from_images(args.images)
        if result:
            print(result)
            sys.exit(0)
        else:
            print(f"❌ {error}")
            sys.exit(1)
