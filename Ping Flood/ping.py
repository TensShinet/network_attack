
import os
import sys
import socket
import struct
import select
import time
import pdb

if sys.platform == "win32":
    # On Windows, the best timer is time.clock()
    default_timer = time.clock
else:
    # On most other platforms the best timer is time.time()
    default_timer = time.time

# From /usr/include/linux/icmp.h; your milage may vary.
ICMP_ECHO_REQUEST = 8  # Seems to be the same on Solaris.


def checksum(source_string):
    """
    A port of the functionality of in_cksum() from ping.c
    Ideally this would act on the string as a series of 16-bit ints (host
    packed), but this works.
    Network data is big-endian, hosts are typically little-endian
    """
    countTo = (int(len(source_string)/2))*2
    sum = 0
    count = 0

    # Handle bytes in pairs (decoding as short ints)
    loByte = 0
    hiByte = 0
    while count < countTo:
        if (sys.byteorder == "little"):
            loByte = source_string[count]
            hiByte = source_string[count + 1]
        else:
            loByte = source_string[count + 1]
            hiByte = source_string[count]
        try:     # For Python3
            sum = sum + (hiByte * 256 + loByte)
        except:  # For Python2
            sum = sum + (ord(hiByte) * 256 + ord(loByte))
        count += 2

    # Handle last byte if applicable (odd-number of bytes)
    # Endianness should be irrelevant in this case
    if countTo < len(source_string):  # Check for odd length
        loByte = source_string[len(source_string)-1]
        try:      # For Python3
            sum += loByte
        except:   # For Python2
            sum += ord(loByte)

    sum &= 0xffffffff  # Truncate sum to 32 bits (a variance from ping.c, which
    # uses signed ints, but overflow is unlikely in ping)

    sum = (sum >> 16) + (sum & 0xffff)    # Add high 16 bits to low 16 bits
    sum += (sum >> 16)                    # Add carry from above (if any)
    answer = ~sum & 0xffff                # Invert and truncate to 16 bits
    answer = socket.htons(answer)

    return answer

def send_one_ping(sock, addr, pid):
    # addr = addr  # socket.gethostbyaddr(addr)

    # 构造 icmp header
    # icmp 的 header 很简单：
    # type(1B) Code(1B) Checksum(2B) identifier(2B) sequence number(2B)
    # 首先给造一个空 header
    data_checksum = 0
    header = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST, 0, data_checksum, pid, 1
    )
    
    # 构造 data
    time_size = struct.calcsize("d")
    data = (50 - time_size) * b'Q'


    data = struct.pack("d", default_timer()) + data
    
    # 计算 checksum
    data_checksum = checksum(header+data)
    # 重新构造 header
    header = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(data_checksum), pid, 1
    )
    packet = header+data
    sock.sendto(packet, (addr, 1))


def receive_ping(sock, pid, timeout):
    timeleft = timeout
    while True:
        select_start = default_timer()
        whatready = select.select([sock], [], [], timeleft)
        howlong_in_select = default_timer() - select_start
        if whatready[0] == []:
            print('timeout')
            return
        
        time_receiver = default_timer()
        rec_packet, addr = sock.recvfrom(1024)
        icmp_header = rec_packet[20:28]
        type, code, recv_chk, packet_id, sequence = struct.unpack(
            "bbHHh", icmp_header
        )


        # 检查 checksum
        header = struct.pack(
            "bbHHh", code, 0, 0, pid, 1
        )
        data = rec_packet[28:]
        chk = checksum(header+data)
        recv_chk = socket.ntohs(recv_chk)

        if recv_chk != chk:
            raise Exception('checksum error!')

        # type != 8 不接受自己的包
        if type != 8 and packet_id == pid:
            bytesInDouble = struct.calcsize("d")
            timeSent = struct.unpack("d", rec_packet[28:28 + bytesInDouble])[0]
            return time_receiver - timeSent

        timeleft = timeleft - howlong_in_select
        if timeleft <= 0:
            return


def ping(addr, timeout=2):
    icmp = socket.getprotobyname("icmp")
    # 权限必须是 root
    try:
        ping_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except socket.error as why:
        errno, msg = why.args
        if errno == 1:
            # Operation not permitted
            msg = msg + (
                " - Note that ICMP messages can only be sent from processes\n"
                " running as root.\n"
            )
            raise socket.error(msg)
        raise  # raise the original error
    pid = os.getpid() & 0xFFFF
    send_one_ping(ping_socket, addr, pid)
    delay = receive_ping(ping_socket, pid, timeout)
    ping_socket.close()
    return delay


def verbose_ping(dest_addr, timeout=2, count=1):

    for i in range(count):
        print("ping %s..." % dest_addr)
        try:
            delay = ping(dest_addr, timeout)
        except Exception as why:
            print(why)
            break
        except socket.gaierror as why1:
            print("failed. (socket error: '%s')" % why1[1])
            break

        if delay == None:
            print("failed. (timeout within %ssec.)" % timeout)
        else:
            delay = delay * 1000
            print("get ping in %0.4fms" % delay)


def main():
    verbose_ping('baidu.com', 2)

if __name__ == "__main__":
    main()
