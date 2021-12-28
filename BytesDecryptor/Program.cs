using System;
using System.IO;
using System.Text;
using xxHashSharp;

string name = "academyfavorscheduleexceltable.bytes";
string password = "AcademyFavorScheduleExcelTable";

byte[] input = Encoding.UTF8.GetBytes(password);
UInt32 hash = xxHash.CalculateHash(input);
byte[] file = File.ReadAllBytes(name);
byte[] key = new MersenneTwister(hash).NextBytes(file.Length);
byte[] decoded = OTP(file, key);
File.WriteAllBytes(name + ".dec", decoded);

byte[] OTP(byte[] inBytes, byte[] keyBytes)
{
    byte[] outBytes = new byte[inBytes.Length];

    for (int i = 0; i < inBytes.Length; i++) {
        outBytes[i] = (byte)(inBytes[i] ^ keyBytes[i]);
    }

    return outBytes;
}
