"""
COSC264 - Client
A command line application operating as a TCP client
Accepts three parameters read from command line: Host(IP or String), port, filename
A Josephs
16 August 2019
"""

import socket
import sys
import os

BUFFSIZE = 4096
HEADERSIZE = 8
MAGICNUM = 0x497E


def get_parameters(parse):
    """
    :param parse: Read three parameters from command line
    :return: IP, Port and File Name
    """
    if len(parse) != 4:
        print("Please enter three arguments to the command line")

    else:
        ip = parse[1]
        port = int(parse[2])
        filename = parse[3]

        print("\nYour input HOST: {}, PORT: {}, FILENAME: {}\n".format(ip, port, filename))

        try:
            address = socket.getaddrinfo(ip, port)
            ip = address[0][4][0]

        except Exception as e:
            print("\nPlease enter a host in the format host in format fileserver.mydomain.nz")
            print("or an a IP in the format 123.1.1.1\n")
            sys.exit()

        if port < 1024 or port > 64000:
            print("\nPlease enter Port value within 1,024 and 64,000\n")
            sys.exit()

        if os.path.exists(filename):
            print("\n{} file already exists in client directory\n".format(filename))
            sys.exit()

        return ip, port, filename


def prepare_file(filename):
    """
    Prepares header file, calls a validity check for the file name
    :param filename: Name of file to be requested from server
    :return: a header file formatted to a 5 Byte array (Magic Number:2 bytes, Type:1 byte,
    File Name Length: 2 Bytes
    """

    file_request = bytearray()

    magic_num = MAGICNUM  # 16 bit, safeguard to check received data FileRequest
    file_request.append(magic_num >> 8)
    file_request.append(magic_num & 0x00FF)

    type_file = 2  # 6 bit
    file_request.append(type_file)

    filename_len = len(filename.encode('utf-8'))  # 2 x 16 bit
    file_valid(filename)
    file_request.append(filename_len >> 8)
    file_request.append(filename_len & 0x00FF)

    file_request += filename.encode('utf-8')

    return file_request


def file_valid(filename):
    """
    Checks file name is not 0 or greater than 1,024 in length. Exit client if False.
    :param filename: File name
    :return: Void.
    """
    if len(filename) < 0 or len(filename) > 1024:
        print("\nPlease use a filename that is longer than 1 and shorter than 1024 characters\n")
        sys.exit()


def create_client(ip, port):
    """
    Build the client and connect.
    :param ip: host IP created in parameters from parsed command line
    :param port: port parsed from command line
    :return: socket
    """
    s = build_socket(port)
    s = connect_socket(s, ip, port)

    return s


def build_socket(port):
    """
    :param port: Parsed from command line
    :return: Socket
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("...establishing connection")

    except Exception as e:
        print("Unable to establish a connection.")
        print("ERROR: {}\n".format(e))
        sys.exit()

    return s


def connect_socket(s, ip, port):
    """
    :param s: Socket
    :param ip: Host IP
    :param port: Port
    :return: socket
    """
    try:
        s.connect((ip, port))
        print("...connection established with HOST {} at PORT {}".format(ip, port))

    except Exception as e:
        print("Unable to establish a connection")
        print("ERROR: {}\n".format(e))
        sys.exit()

    return s


def send_file_request(s, file_request):
    """
    Sending file request byte array to server
    :param s: socket
    :param file_request: byte array with header contents
    :return: Void
    """
    try:
        print("...sending data")
        s.send(file_request)  # send header and filename data
        print("...file request transmitted")

    except Exception as e:
        print("File request not successfully sent to server")
        print("ERROR: {}\n".format(e))
        sys.exit()


def receive_file(s, filename):
    """
    Receives packets of data from server. Calls write function.
    :param s: socket
    :param filename: File Name
    :return: Void.
    """
    try:
        first_received = s.recv(HEADERSIZE)
        s.settimeout(1.0)

    except socket.timeout:
        print("\nMaximum time exceeded for File Request transmission\n")
        s.close()
        sys.exit()

    file_size = verify_receive(first_received)

    try:
        remainder_received = s.recv(BUFFSIZE)
        s.settimeout(1.0)

    except socket.timeout:
        print("\nMaximum time exceeded for File Request transmission\n")
        s.close()
        sys.exit()

    try:
        while len(remainder_received) != 0:
            write_file(remainder_received, filename)
            remainder_received = s.recv(BUFFSIZE)

    except Exception as e:
        print("Unable to receive file data from server")
        print("ERROR: {}\n".format(e))
        s.close()
        sys.exit()

    validate_size(filename, file_size)

    print("File transmission complete\n")


def validate_size(filename, file_size):
    """
    Print statement about data in and data expected
    :param filename: File Name
    :param file_size: Size of file from Header file
    :return: Void.
    """
    data_length = os.path.getsize(filename)
    print("\nFile size: {}, \nData received: {}".format(data_length, file_size))

    return None


def verify_receive(file_in):
    """
    Verification of data received from server. Will also receive a header file
    back if creation parameters are incorrect and will handle with print statement
    :param file_in: File Response byte array from server containing header
    :return: length of the file specified in header
    """
    try:
        magic_num = (file_in[0] << 8) | (file_in[1])
        type_f = file_in[2]
        status = file_in[3]

        valid = True

        if status == 0:
            message = "\nFile does not exist on server"
            valid = False
        if magic_num != MAGICNUM:
            valid = False
            message = "\nInvalid magic number"
        if type_f != 2:
            valid = False
            message = "\nInvalid type number"

        if not valid:
            print(message)

        file_len = (file_in[4] << 24) | (file_in[5] << 16) | (file_in[6] << 8) | (file_in[7])

        print("... header data verification complete")

        return file_len

    except IndexError:
        print("File request returned, please check outgoing data parameters\n")
        sys.exit()

    except Exception as e:
        print("Unable to verify data from server")
        print("ERROR: {}\n".format(e))


def write_file(received_data, filename):
    """
    Writes file to client folder
    :param received_data: data read into client from server
    :param filename: Filename to write file to
    :return: Void.
    """
    try:
        file = open(filename, "ab+")
        file.write(received_data)

        file.close()

    except Exception as e:
        print("Unable to write to file")
        print("ERROR {}\n".format(e))
        sys.exit()


def main():
    """Main Function Call to activate client"""
    parse = sys.argv
    ip, port, filename = get_parameters(parse)
    file_request = prepare_file(filename)
    s = create_client(ip, port)
    send_file_request(s, file_request)
    receive_file(s, filename)

    sys.exit(0)


main()
