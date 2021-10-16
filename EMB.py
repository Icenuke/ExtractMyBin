#!/usr/bin/python3
# -*- coding:utf-8 -*-


from argparse import ArgumentParser
from os import system
from subprocess import check_output


def Output(flname, data):
    '''
        Function to export data record in binary
        :param flname:    Data to export
        :param data:    Data to export
        :return:        None
    '''
    try:
        print('\t[>] Export data')
        with open('%s_shellcode.txt' %(flname), 'w') as fl:
            fl.write(data)

        print('\t[>] Shellcode exported in %s_shellcode.txt file' %(flname))

    except Exception as e:
        print(e)


def CheckNullBytes(data):
    '''
        Function to check if null bytes are present
        :param data:    Data to check null bytes
        :return:        Data without null byte
    '''
    try:
        print('\t[>] Check for null byte')
        if '\\x00' in data:
            print('\t[!] NULL BYTE DETECTED')

        else:
            print('\t[>] No null byte detected')


    except Exception as e:
        print(e)


def CBinShellcode(flname, data):
    '''
        Function to create C binary file with shellcode
        :param data:    Data used to create C binary
        :return:        None
    '''
    try:
        # init code C to test shellcode
        codeC4Shellcode = '''
        char code[] = "%s";
        int main(int argc, char **argv){
        int (*func)();
        func = (int (*)()) code;
        (int)(*func)();}
        ''' %(data)

        print('\t[>] Create C code file')
        with open('%s_code.c'%(flname), 'w') as cfl:
            cfl.write(codeC4Shellcode)

        print('\t[>] Code file created')

        # init cmd line to create C file
        cmd = 'gcc -o %s_code.bin %s_code.c -fno-stack-protector -z execstack -no-pie' %(flname, flname)
        # create binary shellcode
        system(cmd)

        return '%s_code.bin' %(flname)

    except Exception as e:
        print(e)


def ExecutionBin(bin):
    '''
        Function to execute the binary create
        with the extraction of  the data / shellcode
        :param bin:     Execute the binary file
        :return:
    '''
    try:
        print('\t[>] Try to exec %s' % (bin))
        # try to execute the binary
        ret = check_output(['./%s' %(bin)])

    except Exception as e:
        print(e)


def ExtractOPCode(originakBins):
    '''
        Function to extract OPCode from binary / binaries
        :param originakBin:     Originals binaries use to extract Shellcode
        :return:                Shellcode data
    '''
    try:
        print('\t[>] Extraction from %s' % (binary))
        # open in read byte mode the binary
        with open(originakBins, 'rb') as bf:
            # read all the file and convert in hexadecimal
            # 8192 -> the size before OPCode of asm instruction equivalent of 4096
            data = bf.read().hex()[8192::]

        # escape the end of the file starting by 010000000400f1ff
        data = data[:data.index('010000000400f1ff')]

        # init var shcode to create and concat all OPCode
        shcode = ''

        # itering in all char by step of 2 and add \x in string
        for i in range(0, len(data), 2):
            shcode += '-\\x%s%s' %(data[i], data[i+1])

        # create temporary list to escape the null byte at the end
        # revert the list
        tmpLstOpcode = shcode.split('-')[::-1]

        # init check variable for the while
        checkOPcode = False
        # init counter
        cnt = 0

        # iter while nullbyte has find,
        # when the first opcode is find go out the loop
        while checkOPcode == False:
            # if the opcode different of null byte check == True
            if tmpLstOpcode[cnt] != '\\x00':
                checkOPcode = True

            else:
                cnt += 1

        # excape the nullbytes
        tmpLstOpcode = tmpLstOpcode[cnt::]
        # revert again the list without null bytes
        shcode = ''.join(tmpLstOpcode[::-1])

        print('\t[>] %s SHELLCODE: \n\t%s' %(binary, shcode))
        return shcode

    except Exception as e:
        print(e)


if __name__ == "__main__":
    print('''
         ________  _________ 
        |  ___|  \/  || ___ \\
        | |__ | .  . || |_/ /
        |  __|| |\/| || ___ \\
        | |___| |  | || |_/ /
        \____/\_|  |_/\____/ 
                Developed by Icenuke
    ''')

    try:
        # Section to parse arg which can be passed to the script
        parser = ArgumentParser()
        parser.add_argument('-c', '--check', action='store_true',
                            help='Check null byte and ask if the extract should be perform'
                                 'if nothin xas passed then the check of null bytes wasn\'t perform')
        parser.add_argument('-o', '--output', action='store_true',
                            help='Output file to record the opcode')
        parser.add_argument('-b', '--bin', action='store_true',
                            help='Create C binary with shellcode (don\'t perfom totally now with Windows)')
        parser.add_argument('-e', '--exec', action='store_true',
                            help='Like -b option with execution (don\'t perfom totally now with Windows)')
        parser.add_argument('binary', nargs='+', type=str,
                            help='Binary(ies) to extract data')
        args = parser.parse_args()

        print('\t[>] Start shellcode extraction')

        # itering in all binaries pass in parameter
        for binary in args.binary:
            # Call function to record the shellcode
            shellcode = ExtractOPCode(binary)

            # if check was passed then go check null bytes
            if args.check:
                CheckNullBytes(shellcode)

            # if bin was passed then go to create the C file to test Shellcode
            if args.bin:
                # flnames list of filenames created
                CBinShellcode(binary, shellcode)

            # if exec xas passed then go to create Cbin file and try
            # to execute the bin file created before
            if args.exec:
                fname = CBinShellcode(binary, shellcode)
                print(fname)
                ExecutionBin(fname)

            # Export shellcode in a text file
            if args.output:
                Output(binary, shellcode)

            print('\n')

    except Exception as e:
        print(e)
