/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.rlsecurity.modules.argon2.util;

/**
 *
 * @author Paul G. Allen <pgallen@gmail.com>
 */
public class Argon2Defs
{
    public static final int ARGON2_MIN_LANES = 1;
    public static final int ARGON2_MAX_LANES  = 0xFFFFFF;

    /* Minimum and maximum number of threads */
    public static final int ARGON2_MIN_THREADS  = 1;
    public static final int ARGON2_MAX_THREADS  = 0xFFFFFF;

    /* Number of synchronization points between lanes per pass */
    public static final int ARGON2_SYNC_POINTS  = 4;

    /* Minimum and maximum digest size in bytes */
    public static final int ARGON2_MIN_OUTLEN = 4;
    public static final int ARGON2_MAX_OUTLEN = 0xFFFFFFFF;

    /* Minimum and maximum number of memory blocks (each of BLOCK_SIZE bytes) */
    public static int ARGON2_MIN_MEMORY  = (2 * ARGON2_SYNC_POINTS); /* 2 blocks per slice */

    public static long ARGON2_MIN (long a, long b)
    {
        return (a) < (b) ? (a) : (b);
    }

    /* Max memory size is addressing-space/2, topping at 2^32 blocks (4 TB) */
    public static long ARGON2_MAX_MEMORY_BITS()
    {
        return Runtime.getRuntime().totalMemory();
    }

    public static final long ARGON2_MAX_MEMORY = Argon2Defs.ARGON2_MIN (0xFFFFFFFF, 1 << ARGON2_MAX_MEMORY_BITS());

    /* Minimum and maximum number of passes */
    public static final int ARGON2_MIN_TIME = 1;
    public static final int ARGON2_MAX_TIME = 0xFFFFFFFF;

    /* Minimum and maximum password length in bytes */
    public static final int ARGON2_MIN_PWD_LENGTH = 0;
    public static final int ARGON2_MAX_PWD_LENGTH = 0xFFFFFFFF;

    /* Minimum and maximum associated data length in bytes */
    public static final int ARGON2_MIN_AD_LENGTH = 0;
    public static final int ARGON2_MAX_AD_LENGTH = 0xFFFFFFFF;

    /* Minimum and maximum salt length in bytes */
    public static final int ARGON2_MIN_SALT_LENGTH = 8;
    public static final int MAX_SALT_LENGTH = 0xFFFFFFFF;

    /* Minimum and maximum key length in bytes */
    public static final int ARGON2_MIN_SECRET = 0;
    public static final int ARGON2_MAX_SECRET = 0xFFFFFFFF;

    /* Flags to determine which fields are securely wiped (default = no wipe). */
    public static final int ARGON2_DEFAULT_FLAGS = 0;
    public static final int ARGON2_FLAG_CLEAR_PASSWORD  = 0;
    public static final int ARGON2_FLAG_CLEAR_SECRET  = 1;
}
