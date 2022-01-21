/*  That class provides getting digest from the message
    MD5 processes input information in 512-bit groups, and each group is divided into 16 32-bit subgroups.
    After a series of processing, the output of the algorithm consists of four 32-bit groups.
    The cascading group composition of these four 32-bit groups will generate a 128-bit hash value.
*/
public class MD5
    {
        // It's used to get string from byte array after transformation
        static string[] hexs = new string[] { "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f" };
        
        // Magic numbers 
        private static long A = 0x67452301;
        private static long B = 0xefcdab89;
        private static long C = 0x98badcfe;
        private static long D = 0x10325476;

        // Matrix for cycle of rounds
        static int[,] S = new int[4, 4] {{7, 12, 17, 22}, {5, 9, 14, 20}, {4, 11, 16, 23}, {6, 10, 15, 21}};

        private long[] result = new long[4] { A, B, C, D };

        // The main function that receives a string of any length as input
        // and returns a 128-bit hash as output
        public string digest(string inputText)
        {
            byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(inputText);
            int byteLen = inputBytes.Length;

            int groupCount = byteLen / 64;
            long[] groups = new long[16];

            // Basic group calculations
            for (int i = 0; i < groupCount; i++)
            {
                groups = divGroup(inputBytes, i * 64);
                trans(groups);
            }

            // Calculations of tail
            int rest = byteLen % 64;
            byte[] tempBytes = new byte[64];
            if (rest <= 56)
            {
                for (int i = 0; i < rest; i++)
                    tempBytes[i] = inputBytes[byteLen - rest + i];

                if (rest <56)
                {
                    tempBytes[rest] = 1<<7;
                    for (int i = 1; i < 56 - rest; i++)
                        tempBytes[rest + i] = 0;
                }

                long len = (byteLen << 3);
                for (int i = 0; i < 8; i++)
                {
                    tempBytes[56 + i] = (byte)(len & 0xFFL);
                    len = len >> 8;
                }

                groups = divGroup(tempBytes, 0);
                trans(groups);
            }
            else
            {
                for (int i = 0; i < rest; i++)
                    tempBytes[i] = inputBytes[byteLen - rest + i];
                tempBytes[rest] = 1<<7;
                for (int i = rest + 1; i < 64; i++)
                    tempBytes[i] = 0;
                groups = divGroup(tempBytes, 0);
                trans(groups);

                for (int i = 0; i < 56; i++)
                    tempBytes[i] = 0;

                long len = (byteLen << 3);
                for (int i = 0; i < 8; i++)
                {
                    tempBytes[56 + i] = (byte)(len & 0xFFL);
                    len = len >> 8;
                }
                groups = divGroup(tempBytes, 0);
                trans(groups);
            }

            // Converting to string
            string resStr = "";
            long temp;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    temp = result[i] & 0x0F;
                    string a = hexs[temp];
                    result[i] = result[i] >> 4;
                    temp = result[i] & 0x0F;
                    resStr += hexs[temp] + a;
                    result[i] = result[i] >> 4;
                }
            }
            return resStr;

        }

        // This function divides received byte array into 16 64-bits groups
        // and returns each of group as output
        public static long[] divGroup(byte[] inputBytes, int index)
        {
            long[] temp = new long[16];
            for (int i = 0; i < 16; i++)
            {
                temp[i] = inputBytes[4 * i + index] |
                    (inputBytes[4 * i + 1 + index]) << 8 |
                    (inputBytes[4 * i + 2 + index]) << 16 |
                    (inputBytes[4 * i + 3 + index]) << 24;
            }
            return temp;
        }

        // The main transformation function that makes four rounds of cyclic operations
        // This algorithm works only if you apply the logic functions in that order
        private void trans(long[] groups)
        {
            long a = result[0], b = result[1], c = result[2], d = result[3];
            // First round
            a = FF(a, b, c, d, groups[0], S[0, 0], 0xd76aa478);
            d = FF(d, a, b, c, groups[1], S[0, 1], 0xe8c7b756);
            c = FF(c, d, a, b, groups[2], S[0, 2], 0x242070db);
            b = FF(b, c, d, a, groups[3], S[0, 3], 0xc1bdceee);
            a = FF(a, b, c, d, groups[4], S[0, 0], 0xf57c0faf);
            d = FF(d, a, b, c, groups[5], S[0, 1], 0x4787c62a);
            c = FF(c, d, a, b, groups[6], S[0, 2], 0xa8304613);
            b = FF(b, c, d, a, groups[7], S[0, 3], 0xfd469501);
            a = FF(a, b, c, d, groups[8], S[0, 0], 0x698098d8);
            d = FF(d, a, b, c, groups[9], S[0, 1], 0x8b44f7af);
            c = FF(c, d, a, b, groups[10], S[0, 2], 0xffff5bb1);
            b = FF(b, c, d, a, groups[11], S[0, 3], 0x895cd7be);
            a = FF(a, b, c, d, groups[12], S[0, 0], 0x6b901122);
            d = FF(d, a, b, c, groups[13], S[0, 1], 0xfd987193);
            c = FF(c, d, a, b, groups[14], S[0, 2], 0xa679438e);
            b = FF(b, c, d, a, groups[15], S[0, 3], 0x49b40821);

            // Second round
            a = GG(a, b, c, d, groups[1], S[1, 0], 0xf61e2562);
            d = GG(d, a, b, c, groups[6], S[1, 1], 0xc040b340);
            c = GG(c, d, a, b, groups[11], S[1, 2], 0x265e5a51);
            b = GG(b, c, d, a, groups[0], S[1, 3], 0xe9b6c7aa);
            a = GG(a, b, c, d, groups[5], S[1, 0], 0xd62f105d);
            d = GG(d, a, b, c, groups[10], S[1, 1], 0x2441453);
            c = GG(c, d, a, b, groups[15], S[1, 2], 0xd8a1e681); 
            b = GG(b, c, d, a, groups[4], S[1, 3], 0xe7d3fbc8); 
            a = GG(a, b, c, d, groups[9], S[1, 0], 0x21e1cde6); 
            d = GG(d, a, b, c, groups[14], S[1, 1], 0xc33707d6); 
            c = GG(c, d, a, b, groups[3], S[1, 2], 0xf4d50d87); 
            b = GG(b, c, d, a, groups[8], S[1, 3], 0x455a14ed);
            a = GG(a, b, c, d, groups[13], S[1, 0], 0xa9e3e905); 
            d = GG(d, a, b, c, groups[2], S[1, 1], 0xfcefa3f8); 
            c = GG(c, d, a, b, groups[7], S[1, 2], 0x676f02d9);
            b = GG(b, c, d, a, groups[12], S[1, 3], 0x8d2a4c8a);

            // Third round
            a = HH(a, b, c, d, groups[5], S[2, 0], 0xfffa3942); 
            d = HH(d, a, b, c, groups[8], S[2, 1], 0x8771f681); 
            c = HH(c, d, a, b, groups[11], S[2, 2], 0x6d9d6122); 
            b = HH(b, c, d, a, groups[14], S[2, 3], 0xfde5380c); 
            a = HH(a, b, c, d, groups[1], S[2, 0], 0xa4beea44); 
            d = HH(d, a, b, c, groups[4], S[2, 1], 0x4bdecfa9); 
            c = HH(c, d, a, b, groups[7], S[2, 2], 0xf6bb4b60); 
            b = HH(b, c, d, a, groups[10], S[2, 3], 0xbebfbc70); 
            a = HH(a, b, c, d, groups[13], S[2, 0], 0x289b7ec6); 
            d = HH(d, a, b, c, groups[0], S[2, 1], 0xeaa127fa); 
            c = HH(c, d, a, b, groups[3], S[2, 2], 0xd4ef3085); 
            b = HH(b, c, d, a, groups[6], S[2, 3], 0x4881d05);
            a = HH(a, b, c, d, groups[9], S[2, 0], 0xd9d4d039);
            d = HH(d, a, b, c, groups[12], S[2, 1], 0xe6db99e5); 
            c = HH(c, d, a, b, groups[15], S[2, 2], 0x1fa27cf8); 
            b = HH(b, c, d, a, groups[2], S[2, 3], 0xc4ac5665); 

            // Fourth round
            a = II(a, b, c, d, groups[0], S[3, 0], 0xf4292244);
            d = II(d, a, b, c, groups[7], S[3, 1], 0x432aff97);
            c = II(c, d, a, b, groups[14], S[3, 2], 0xab9423a7);
            b = II(b, c, d, a, groups[5], S[3, 3], 0xfc93a039); 
            a = II(a, b, c, d, groups[12], S[3, 0], 0x655b59c3); 
            d = II(d, a, b, c, groups[3], S[3, 1], 0x8f0ccc92); 
            c = II(c, d, a, b, groups[10], S[3, 2], 0xffeff47d); 
            b = II(b, c, d, a, groups[1], S[3, 3], 0x85845dd1); 
            a = II(a, b, c, d, groups[8], S[3, 0], 0x6fa87e4f); 
            d = II(d, a, b, c, groups[15], S[3, 1], 0xfe2ce6e0); 
            c = II(c, d, a, b, groups[6], S[3, 2], 0xa3014314);
            b = II(b, c, d, a, groups[13], S[3, 3], 0x4e0811a1);
            a = II(a, b, c, d, groups[4], S[3, 0], 0xf7537e82);
            d = II(d, a, b, c, groups[11], S[3, 1], 0xbd3af235);
            c = II(c, d, a, b, groups[2], S[3, 2], 0x2ad7d2bb);
            b = II(b, c, d, a, groups[9], S[3, 3], 0xeb86d391);

            // Then add new values to result array
            result[0] += a;
            result[1] += b;
            result[2] += c;
            result[3] += d;
            result[0] = result[0] & 0xFFFFFFFF;
            result[1] = result[1] & 0xFFFFFFFF;
            result[2] = result[2] & 0xFFFFFFFF;
            result[3] = result[3] & 0xFFFFFFFF;
        }

        // The first logic function - (X and Y) or (not(X) and Z)
        private static long F(long x, long y, long z)
        {
            return (x & y) | ((~x) & z);
        }

        // The second logic function - (X and Y) or (not(Z) and Y)
        private static long G(long x, long y, long z)
        {
            return (x & z) | (y & (~z));
        }

        // The third logic function - X xor Y xor Z
        private static long H(long x, long y, long z)
        {
            return x ^ y ^ z;
        }

        // The fourth logic function - Y xor (not(Z) or X)
        private static long I(long x, long y, long z)
        {
            return y ^ (x | (~z));
        }


        // The modified first logic function means a = b + ((a + F (b, c, d) + x + ac) << s)
        // All other functions work in the same way, only they use other logical functions
        private static long FF(long a, long b, long c, long d, long x, int s, long ac)
        {
            a += (F(b, c, d) & 0xFFFFFFFF) + x + ac;
            a = ((a & 0xFFFFFFFF) << s) | ((a & 0xFFFFFFFF) >> (32 - s));
            a += b;
            return (a & 0xFFFFFFFF);
        }

        private static long GG(long a, long b, long c, long d, long x, int s, long ac)
        {
            a += (G(b, c, d) & 0xFFFFFFFF) + x + ac;
            a = ((a & 0xFFFFFFFF) << s) | ((a & 0xFFFFFFFF) >> (32 - s));
            a += b;
            return (a & 0xFFFFFFFF);
        }

        private static long HH(long a, long b, long c, long d, long x, int s, long ac)
        {
            a += (H(b, c, d) & 0xFFFFFFFF) + x + ac;
            a = ((a & 0xFFFFFFFF) << s) | ((a & 0xFFFFFFFF) >> (32 - s));
            a += b;
            return (a & 0xFFFFFFFF);
        }

        private static long II(long a, long b, long c, long d, long x, int s, long ac)
        {
            a += (I(b, c, d) & 0xFFFFFFFF) + x + ac;
            a = ((a & 0xFFFFFFFF) << s) | ((a & 0xFFFFFFFF) >> (32 - s));
            a += b;
            return (a & 0xFFFFFFFF);
        }
    }