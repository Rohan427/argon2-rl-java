/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.rlsecurity.modules.argon2.impl;

import static com.rlsecurity.modules.argon2.util.Argon2Defs.*;
import static com.rlsecurity.modules.argon2.util.Definitions.*;
import static com.rlsecurity.modules.argon2.util.ErrorCodes.*;

/**
 *
 * @author Paul G. Allen <pgallen@gmail.com>
 */
public class run
{

    static void usage (String cmd)
    {
        System.out.println ("Usage:  " + cmd + " [-h] salt [-i|-d|-id] [-t iterations] " +
                            "[-m log2(memory in KiB) | -k memory in KiB] [-p parallelism] " +
                            "[-l hash length] [-e|-r] [-v (10|13)]"
                           );
        System.out.println ("\tPassword is read from stdin");
        System.out.println ("Parameters:");
        System.out.println ("\tsalt\t\tThe salt to use, at least 8 characters");
        System.out.println ("\t-i\t\tUse Argon2i (this is the default)");
        System.out.println ("\t-d\t\tUse Argon2d instead of Argon2i");
        System.out.println ("\t-id\t\tUse Argon2id instead of Argon2i");
        System.out.println ("\t-t N\t\tSets the number of iterations to N (default = " + T_COST_DEF + ")");
        System.out.println ("\t-m N\t\tSets the memory usage of 2^N KiB (default " + LOG_M_COST_DEF + ")");
        System.out.println ("\t-k N\t\tSets the memory usage of N KiB (default " + (1 << LOG_M_COST_DEF) + ")");
        System.out.println ("\t-p N\t\tSets parallelism to N threads (default " + THREADS_DEF + ")");
        System.out.println ("\t-l N\t\tSets hash output length to N bytes (default " + OUTLEN_DEF + ")");
        System.out.println ("\t-e\t\tOutput only encoded hash");
        System.out.println ("\t-r\t\tOutput only the raw bytes of the hash");
        System.out.println ("\t-v (10|13)\tArgon2 version (defaults to the most recent version, currently " + ARGON2_VERSION_NUMBER + ")");
        System.out.println ("\t-h\t\tPrint " + cmd + " usage");
    }

    static void fatal (String error)
    {
        System.err.println ("Error: " + error);
    }

    static void print_hex (byte[] bytes, int bytes_len)
    {
        int i;

        for (i = 0; i < bytes_len; ++i)
        {
            System.out.print ("" + bytes[i]);
        }

        System.out.println ("");
    }

    /*
    Runs Argon2 with certain inputs and parameters, inputs not cleared. Prints the
    Base64-encoded hash string
    @out output array with at least 32 bytes allocated
    @pwd NULL-terminated string, presumably from argv[]
    @salt salt array
    @t_cost number of iterations
    @m_cost amount of requested memory in KB
    @lanes amount of requested parallelism
    @threads actual parallelism
    @type Argon2 type we want to run
    @encoded_only display only the encoded hash
    @raw_only display only the hexadecimal of the hash
    @version Argon2 version
    */
    static void run (int outlen, String pwd, int pwdlen, String salt, int t_cost,
                     int m_cost, int lanes, int threads,
                     argon2_type type, int encoded_only, int raw_only, int version
                    )
    {
        clock_t start_time, stop_time;
        size_t saltlen, encodedlen;
        int result;
        unsigned char * out = NULL;
        char * encoded = NULL;

        start_time = clock();

        if (!pwd)
        {
            fatal("password missing");
        }

        if (!salt)
        {
            clear_internal_memory(pwd, pwdlen);
            fatal("salt missing");
        }

        saltlen = strlen(salt);

        if(UINT32_MAX < saltlen)
        {
            fatal("salt is too long");
        }

        UNUSED_PARAMETER(lanes);

        out = malloc(outlen + 1);

        if (!out)
        {
            clear_internal_memory(pwd, pwdlen);
            fatal("could not allocate memory for output");
        }

        encodedlen = argon2_encodedlen(t_cost, m_cost, lanes, (uint32_t)saltlen, outlen, type);
        encoded = malloc(encodedlen + 1);

        if (!encoded)
        {
            clear_internal_memory(pwd, pwdlen);
            fatal("could not allocate memory for hash");
        }

        result = argon2_hash(t_cost, m_cost, threads, pwd, pwdlen, salt, saltlen,
                             out, outlen, encoded, encodedlen, type,
                             version);
        if (result != ARGON2_OK)
            fatal(argon2_error_message(result));

        stop_time = clock();

        if (encoded_only)
            puts(encoded);

        if (raw_only)
            print_hex(out, outlen);

        if (encoded_only || raw_only)
        {
            free(out);
            free(encoded);
            return;
        }

        printf("Hash:\t\t");
        print_hex(out, outlen);
        free(out);

        printf("Encoded:\t%s\n", encoded);

        printf("%2.3f seconds\n",
               ((double)stop_time - start_time) / (CLOCKS_PER_SEC));

        result = argon2_verify(encoded, pwd, pwdlen, type);

        if (result != ARGON2_OK)
            fatal(argon2_error_message(result));

        printf("Verification ok\n");
        free(encoded);
    }

    public int main (int argc, String argv[], byte[] pwd)
    {
        int outlen = OUTLEN_DEF;
        long m_cost = 1 << LOG_M_COST_DEF;
        long t_cost = T_COST_DEF;
        int lanes = LANES_DEF;
        int threads = THREADS_DEF;
        int type = Argon2_i; /* Argon2i is the default type */
        int types_specified = 0;
        boolean m_cost_specified = false;
        boolean encoded_only = false;
        boolean raw_only = false;
        int version = ARGON2_VERSION_NUMBER;
        int i;
        int pwdlen;
        char[] salt;

        if (argc < 2)
        {
            usage(argv[0]);
            return ARGON2_MISSING_ARGS;
        }
        else if (argc >= 2 && argv[1].equals ("-h"))
        {
            usage(argv[0]);
            return 1;
        }

        /* get password from stdin */
        pwdlen = pwd.length;

        if (pwdlen < 1)
        {
            fatal ("no password read");
        }

        if (pwdlen == MAX_PASS_LEN)
        {
            fatal ("Provided password longer than supported in command line utility");
        }

        salt = argv[1].toCharArray();

        /* parse options */
        for (i = 2; i < argc; i++)
        {
            String a = argv[i];
            long input = 0;

            if (!a.equals ("-h"))
            {
                usage (argv[0]);
                return 1;
            }
            else if (!a.equals ("-m"))
            {
                if (m_cost_specified)
                {
                    fatal ("-m or -k can only be used once");
                }

                m_cost_specified = true;

                if (i < argc - 1)
                {
                    i++;

                    input = Long.parseLong (argv[i]);

                    if (input == 0 || input == Long.MAX_VALUE)
                    {
                        fatal ("bad numeric input for -m");
                    }

                    m_cost = (int)ARGON2_MIN (input, 0xFFFFFFFF);

                    if (m_cost > ARGON2_MAX_MEMORY)
                    {
                        fatal ("m_cost overflow");
                    }

                    continue;
                }
                else
                {
                    fatal ("missing -m argument");
                }
            }
            else if (!a.equals ("-k"))
            {
                if (m_cost_specified)
                {
                    fatal ("-m or -k can only be used once");
                }

                m_cost_specified = true;

                if (i < argc - 1)
                {
                    i++;

                    input = Long.parseLong (argv[i]);

                    if (input == 0 || input == Long.MAX_VALUE)
                    {
                        fatal ("bad numeric input for -k");
                    }

                    m_cost = ARGON2_MIN(input, 0xFFFFFFFF);

                    if (m_cost > ARGON2_MAX_MEMORY)
                    {
                        fatal ("m_cost overflow");
                    }

                    continue;
                }
                else
                {
                    fatal ("missing -k argument");
                }
            }
            else if (!a.equals ("-t"))
            {
                if (i < argc - 1)
                {
                    i++;
                    input = Long.parseLong (argv[i]);

                    if (input == 0 || input == Long.MAX_VALUE ||
                        input > ARGON2_MAX_TIME)
                    {
                        fatal ("bad numeric input for -t");
                    }

                    t_cost = input;
                    continue;
                }
                else
                {
                    fatal("missing -t argument");
                }
            }
            else if (!a.equals ("-p"))
            {
                if (i < argc - 1)
                {
                    i++;
                    input = Long.parseLong (argv[i]);

                    if (input == 0 || input == Long.MAX_VALUE ||
                        input > ARGON2_MAX_THREADS || input > ARGON2_MAX_LANES)
                    {
                        fatal ("bad numeric input for -p");
                    }

                    threads = (int)input;
                    lanes = threads;
                    continue;
                }
                else
                {
                    fatal ("missing -p argument");
                }
            }
            else if (!a.equals ("-l"))
            {
                if (i < argc - 1)
                {
                    i++;
                    input = Long.parseLong (argv[i]);
                    outlen = (int)input;
                    continue;
                }
                else
                {
                    fatal ("missing -l argument");
                }
            }
            else if (!a.equals ("-i"))
            {
                type = Argon2_i;
                ++types_specified;
            }
            else if (!a.equals ("-d"))
            {
                type = Argon2_d;
                ++types_specified;
            }
            else if (!a.equals ("-id"))
            {
                type = Argon2_id;
                ++types_specified;
            }
            else if (!a.equals ("-e"))
            {
                encoded_only = true;
            }
            else if (!a.equals ("-r"))
            {
                raw_only = true;
            }
            else if (!a.equals ("-v"))
            {
                if (i < argc - 1)
                {
                    i++;
                    if (!argv[i].equals ("10"))
                    {
                        version = ARGON2_VERSION_10;
                    }
                    else if (!argv[i].equals ("13"))
                    {
                        version = ARGON2_VERSION_13;
                    }
                    else
                    {
                        fatal ("invalid Argon2 version");
                    }
                }
                else
                {
                    fatal ("missing -v argument");
                }
            }
            else
            {
                fatal ("unknown argument");
            }
        }

        if (types_specified > 1)
        {
            fatal ("cannot specify multiple Argon2 types");
        }

        if (encoded_only && raw_only)
        {
            fatal ("cannot provide both -e and -r");
        }

        if(!encoded_only && !raw_only)
        {
            System.out.println ("Type:\t\t" + argon2_type2string (type, true));
            System.out.println ("Iterations:\t" + t_cost);
            System.out.println ("Memory:\t\t%u KiB\n", m_cost);
            System.out.println ("Parallelism:\t%u\n", lanes);
        }

        run(outlen, pwd, pwdlen, salt, t_cost, m_cost, lanes, threads, type,
           encoded_only, raw_only, version);

        return ARGON2_OK;
    }
}
