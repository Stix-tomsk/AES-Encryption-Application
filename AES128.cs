/*  That class provides encrypting/decrypting according AES standart.
    First all the source data is converted to bytes and divided into 128-bit blocks (4 by 4 matrices).
    Then every block goes through some transforming functions after which it becomes encrypted.
    When each block has passed the transformation, they are assembled back, but already in the ciphertext.

    There are four transforming functions: SubBytes(), ShiftRows(), MixColumns() and AddRoundKey().
    And several additional functions in my implementation : keyExpansion(), shift() and six functions for multiplication in Galois field.
*/

public class AES128
    {
        // nk is the key length in 32-bit words
        // nb is the number of columns in 32-bit words as well
        // nr is the number of rounds (nr value depends of key length)
        const int nk = 4, nb = 4, nr = 10;

        // sbox is the contant table representing a finite field (Galois field)
        // This table is used in SubBytes and keyExpansion functions

        /* In Galois field every element is polynomial term
           this means that multiplication, addition, subtraction and division (excluding division by zero)
           are defined and satisfy the rules of arithmetic known as the field axioms.
        */
        byte[] sbox = new byte[] {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        };

        // invSbox table is inverse version of sbox table
        // This table is used in InvSubBytes function
        byte[] invSbox = new byte[] {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        };

        // rcon table is another constant table that's used in keyExpansion function
        byte[,] rcon = new byte[,] {
            { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 },
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
        };

        // The main encryption function that takes a string of length from 0 to 4080 characters and a key of any-length as input
        // and returns the ciphertext as output
        public string encrypt(string inputText, string key)
        {
            byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(inputText);
            int blockCount = inputBytes.Length / 16;
            int tailLength = inputBytes.Length % 16;
            ArrayList outputBytesList = new ArrayList();
            
            // Encrypting of the basic blocks
            for (int i = 0; i < blockCount; i++)
            {
                // Creating the 128-bit block and encrypting  it
                byte[] state = new byte[16];
                for (int j = 0; j < 16; j++)
                    state[j] = inputBytes[j + 16 * i];
                byte[] tmp = encryptBlock(state, key);
                outputBytesList.AddRange(tmp);
            }

            // Encrypting of the tail
            byte[] tailState = new byte[16];
            for (int i = 0; i < tailLength; i++)
                tailState[i] = inputBytes[i + 16 * blockCount];
            for (int i = tailLength; i < 16; i++)
                tailState[i] = 0;
            
            byte[] tailTmp = encryptBlock(tailState, key);
            outputBytesList.AddRange(tailTmp);

            // The last two bytes are used to store the original length of the text
            // It happens due to division by 16 and the remainder of division by 16, so the maximum text length can be 255*16 = 4080
            outputBytesList.Add(Convert.ToByte(inputBytes.Length / 16));
            outputBytesList.Add(Convert.ToByte(inputBytes.Length % 16));

            // Converting result into the base64 string
            byte[] outputBytes = new byte[outputBytesList.Count];
            for (int i = 0; i < outputBytesList.Count; i++)
                outputBytes[i] = Convert.ToByte(outputBytesList[i]);

            string outputText = Convert.ToBase64String(outputBytes);
            
            return outputText;
        }

        // The main decryption function that takes a ciphertext and the key, that was used to encrypt, as input
        // and returns the decrypted text as output
        public string decrypt(string cryptedText, string key)
        {
            byte[] inputBytes = Convert.FromBase64String(cryptedText);

            // Getting source text length from two last byte of ciphertext
            int sourceTextLength = inputBytes[inputBytes.Length - 1] + inputBytes[inputBytes.Length - 2] * 16;
            int blockCount = inputBytes.Length / 16;
            int tailLength = inputBytes.Length % 16;
            ArrayList outputBytesList = new ArrayList();

            // Decrypting of the basic blocks
            for (int i = 0; i < blockCount; i++)
            {
                byte[] state = new byte[16];
                for (int j = 0; j < 16; j++)
                    state[j] = inputBytes[j + 16 * i];
                byte[] tmp = decryptBlock(state, key);
                outputBytesList.AddRange(tmp);
            }

            // Decrypting of the tail
            byte[] tailState = new byte[16];
            for (int i = 0; i < tailLength; i++)
                tailState[i] = inputBytes[i + 16 * blockCount];
            for (int i = tailLength; i < 16; i++)
                tailState[i] = 0;

            byte[] tailTmp = decryptBlock(tailState, key);
            outputBytesList.AddRange(tailTmp);

            // Converting result into the string
            byte[] outputBytes = new byte[sourceTextLength];
            for (int i = 0; i < sourceTextLength; i++)
                outputBytes[i] = Convert.ToByte(outputBytesList[i]);


            string outputText = System.Text.Encoding.UTF8.GetString(outputBytes);
            return outputText;
        }

        // This function receives a byte array and a string key as input
        // and returns the encrypted byte array as output
        public byte[] encryptBlock(byte[] inputBytes, string key)
        {
            MD5 md5 = new MD5();

            // The hash of the original key is used as the encryption key
            // That's why the original key can be any length
            string hash = md5.digest(key);

            // state is the block we are working with and where the intermediate results are stored
            byte[,] state = new byte[4, nb];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < nb; j++)
                    state[i, j] = inputBytes[i + 4 * j];
            }
            
            byte[,] keySchedule = keyExpansion(hash);

            // To encrypt a block of bytes it's necessary to apply these functions in that order
            state = addRoundKey(state, keySchedule);
            for (int i = 1; i < nr; i++)
            {
                state = subBytes(state, 0);
                state = shiftRows(state, 0);
                state = mixColumn(state, 0);
                state = addRoundKey(state, keySchedule, i);
            }
            state = subBytes(state, 0);
            state = shiftRows(state, 0);
            state = addRoundKey(state, keySchedule, nr);

            byte[] outputBytes = new byte[16];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < nb; j++)
                    outputBytes[i + 4 * j] = state[i, j];
            }
            return outputBytes;
        }

        public byte[] decryptBlock(byte[] inputBytes, string key)
        {
            MD5 md5 = new MD5();
            string hash = md5.digest(key);
            byte[,] state = new byte[4, nb];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < nb; j++)
                    state[i, j] = inputBytes[i + 4 * j];
            }
            byte[,] keySchedule = keyExpansion(hash);

            // To decrypt a block of bytes it's necessary to apply the functions inverse to those in reverse order
            state = addRoundKey(state, keySchedule, nr);
            int rnd = nr - 1;
            while(rnd >= 1)
            {
                state = shiftRows(state, 1);
                state = subBytes(state, 1);
                state = addRoundKey(state, keySchedule, rnd);
                state = mixColumn(state, 1);
                rnd--;
            }
            state = shiftRows(state, 1);
            state = subBytes(state, 1);
            state = addRoundKey(state, keySchedule, rnd);

            byte[] outputBytes = new byte[16];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < nb; j++)
                    outputBytes[i + 4 * j] = state[i, j];
            }

            return outputBytes;
        }

        // This function necessary to create a key schedule
        // Key schedule is a long table consisting of Nb * (Nr + 1) columns or (Nr + 1) blocks
        // It's used in addRoundKey function
        public byte[,] keyExpansion(string key)
        {
            // The first block of key schedule is filled based on the secret key 
            // The key must have 16-byte length, so the algorithm makes a key from every second character
            byte[] keyBytes = new byte[16];
            byte[] temp = System.Text.Encoding.UTF8.GetBytes(key);
            for (int i = 0; i < 16; i++)
                keyBytes[i] = temp[i*2];
            if (temp.Length < 4 * nk)
            {
                for (int i = temp.Length; i < 16; i++)
                    keyBytes[i] = 0x00;
            }

            byte[,] keySchedule = new byte[4, nb * (nr + 1)];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < nk; j++)
                    keySchedule[i, j] = keyBytes[i + 4 * j];
            }


            // All other columns are filled with their own algorithm
            // If the column number is a multiple of Nk value (in this case, every fourth), then the previous column is taken,
            // a cyclic left shift is performed over it by one element,
            // then all the bytes of the column are replaced with the corresponding ones from the Sbox table
            // Next an XOR operation is performed between the columns: col[i-nk], col[i-1] and rcon[i/nk-1]
            // For the rest of the columns, XOR is performed between the columns col[i-nk] and col[i-1]
            for (int col = nk; col < nb * (nr + 1); col++)
            {
                if (col % nk == 0)
                {
                    byte[] tempRow = new byte[4];
                    for (int i = 0; i < 4; i++)
                    {
                        tempRow[i] = keySchedule[i, col - 1];
                    }
                    tempRow = shift(tempRow, 1, 0);
                    for (int i = 0; i < 4; i++)
                    {
                        for (int j = 0; j < 4; j++)
                            tempRow[i] = sbox[tempRow[i]];
                    }

                    for (int row = 0; row < 4; row++)
                    {
                        int s = (keySchedule[row, col - nk]) ^ (tempRow[row]) ^ (rcon[row, col / nk - 1]);
                        keySchedule[row, col] = Convert.ToByte(s);
                    }

                }
                else
                {
                    for (int row = 0; row < 4; row++)
                    {
                        int s = keySchedule[row, col - nk] ^ keySchedule[row, col - 1];
                        keySchedule[row, col] = Convert.ToByte(s);
                    }
                }
            }
            return keySchedule;

        }

        // This transforming function takes one matrix from the key schedule and adds it element by element to the state matrix
        // Addition in the Galois field is equivalent to xor operation
        public byte[,] addRoundKey(byte[,] state, byte[,] keySchedule, int round = 0)
        {
            for (int i = 0; i < nk; i++)
            {
                int col = nb * round + i;
                state[0, i] = Convert.ToByte(state[0, i] ^ keySchedule[0, col]);
                state[1, i] = Convert.ToByte(state[1, i] ^ keySchedule[1, col]);
                state[2, i] = Convert.ToByte(state[2, i] ^ keySchedule[2, col]);
                state[3, i] = Convert.ToByte(state[3, i] ^ keySchedule[3, col]);
            }

            return state;
        }

        // This function performs a cyclic shift in the state matrix to the left by 1 element for the first row,
        // by 2 for the second and by 3 for the third, the zero row is not shifted
        // If it's decrypting the shift is performed to the right
        public byte[,] shiftRows(byte[,] state, int inv)
        {
            int count = 1;

            if (inv == 0) // Encrypting
            {
                for (int i = 1; i < nb; i++)
                {
                    byte[] stringFromState = new byte[4];
                    for (int j = 0; j < 4; j++)
                        stringFromState[j] = state[i, j];
                    stringFromState = shift(stringFromState, count, 0);
                    for (int j = 0; j < 4; j++)
                        state[i, j] = stringFromState[j];
                    count += 1;
                }
            }
            else // Decrypting
            {
                for (int i = 1; i < nb; i++)
                {
                    byte[] stringFromState = new byte[4];
                    for (int j = 0; j < 4; j++)
                        stringFromState[j] = state[i, j];
                    stringFromState = shift(stringFromState, count, 1);
                    for (int j = 0; j < 4; j++)
                        state[i, j] = stringFromState[j];
                    count += 1;
                }
            }

            return state;
        }
        
        // Additional function for shiftRows that does shift {count} times 
        public byte[] shift(byte[] stateString, int count, int dir)
        {
            byte[] ar = stateString;
            if (dir == 0) // Left
            {
                for (int i = 0; i < count; i++)
                {
                    byte temp = ar[0];
                    for (int j = 0; j < ar.Length - 1; j++)
                        ar[j] = ar[j + 1];
                    ar[ar.Length - 1] = temp;
                }
            }
            else // Right
            {
                for (int i = 0; i < count; i++)
                {
                    byte temp = ar[ar.Length - 1];
                    for (int j = ar.Length - 1; j > 0; j--)
                        ar[j] = ar[j - 1];
                    ar[0] = temp;
                }
            }
            return ar;
        }

        // This function replaces each element of the state matrix with the corresponding element of the SBox table
        // if it's decrypting the replace is performed from invSbox table
        public byte[,] subBytes(byte[,] state, int inv) 
        {
            byte[] box = new byte[256];

            if (inv == 0)
                box = sbox;
            else
                box = invSbox;

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                    state[i, j] = box[state[i, j]];
            }

            return state;
        }

        // Within the framework of this transformation, each column in state matrix is represented as a polynomial
        // and multiplied in the Galois field modulo x^4 + 1 with a fixed polynomial 3x^3 + x^2 + x + 2
        // To decrypt it's multiplied with the reverse formula
        public byte[,] mixColumn(byte[,] state, int inv)
        {
            for (int i = 0; i < nb; i++)
            {
                byte s0, s1, s2, s3;
                if (inv == 0)
                {
                    s0 = Convert.ToByte(mulBy02(state[0, i]) ^ mulBy03(state[1, i]) ^ state[2, i] ^ state[3, i]);
                    s1 = Convert.ToByte(state[0, i] ^ mulBy02(state[1, i]) ^ mulBy03(state[2, i]) ^ state[3, i]);
                    s2 = Convert.ToByte(state[0, i] ^ state[1, i] ^ mulBy02(state[2, i]) ^ mulBy03(state[3, i]));
                    s3 = Convert.ToByte(mulBy03(state[0, i]) ^ state[1, i] ^ state[2, i] ^ mulBy02(state[3, i]));
                }
                else
                {
                    s0 = Convert.ToByte(mulBy0e(state[0,i]) ^ mulBy0b(state[1,i]) ^ mulBy0d(state[2,i]) ^ mulBy09(state[3,i]));
                    s1 = Convert.ToByte(mulBy09(state[0,i]) ^ mulBy0e(state[1,i]) ^ mulBy0b(state[2,i]) ^ mulBy0d(state[3,i]));
                    s2 = Convert.ToByte(mulBy0d(state[0,i]) ^ mulBy09(state[1,i]) ^ mulBy0e(state[2,i]) ^ mulBy0b(state[3,i]));
                    s3 = Convert.ToByte(mulBy0b(state[0,i]) ^ mulBy0d(state[1,i]) ^ mulBy09(state[2,i]) ^ mulBy0e(state[3,i]));
                }

                state[0,i] = s0;
                state[1,i] = s1;
                state[2,i] = s2;
                state[3,i] = s3;
            }

            return state;
        }

        // mulBy__ functions for multiplying by number in Galua space
        // For example, 0x03*num = (0x02 + 0x01)num = num*0x02 + num*0x01
        // Addition in Galua field is oparetion XOR 
        public byte mulBy02(byte num)
        {
            int res;
            if (num < 0x80)
                res = num << 1;
            else
                res = (num << 1) ^ 0x1b;
            return Convert.ToByte(res % 0x100);
        }
        public byte mulBy03(byte num)
        {
            return Convert.ToByte(mulBy02(num) ^ num);
        }
       
        // Using multiply by 3 and following to get new values doesn't work, so
        public byte mulBy09(byte num)
        {
            // Same as mulBy03(num) ^ mulBy03(num) ^ mulBy03(num)
            return Convert.ToByte(mulBy02(mulBy02(mulBy02(num))) ^ num);
        }
        public byte mulBy0b(byte num)
        {
            // Same as mulBy09(num) ^ mulBy02(num)
            return Convert.ToByte(mulBy02(mulBy02(mulBy02(num))) ^ mulBy02(num) ^ num);
        }
        public byte mulBy0d(byte num)
        {
            // Same as mulBy0b(num) ^ mulBy02(num)
            return Convert.ToByte(mulBy02(mulBy02(mulBy02(num))) ^ mulBy02(mulBy02(num)) ^ num);
        }
        public byte mulBy0e(byte num)
        {
            // Same as mulBy0d(num) ^ num
            return Convert.ToByte(mulBy02(mulBy02(mulBy02(num))) ^ mulBy02(mulBy02(num)) ^ mulBy02(num));
        }
    }