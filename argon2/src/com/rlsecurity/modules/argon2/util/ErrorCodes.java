/*
 * To change this license header; choose License Headers in Project Properties.
 * To change this template file; choose Tools | Templates
 * and open the template in the editor.
 */
package com.rlsecurity.modules.argon2.util;

/**
 *
 * @author Paul G. Allen <pgallen@gmail.com>
 */
public class ErrorCodes
{
    public static final int ARGON2_OK = 0;

    public static final int ARGON2_OUTPUT_PTR_NULL = -1;

    public static final int ARGON2_OUTPUT_TOO_SHORT = -2;
    public static final int ARGON2_OUTPUT_TOO_LONG = -3;

    public static final int ARGON2_PWD_TOO_SHORT = -4;
    public static final int ARGON2_PWD_TOO_LONG = -5;

    public static final int ARGON2_SALT_TOO_SHORT = -6;
    public static final int ARGON2_SALT_TOO_LONG = -7;

    public static final int ARGON2_AD_TOO_SHORT = -8;
    public static final int ARGON2_AD_TOO_LONG = -9;

    public static final int ARGON2_SECRET_TOO_SHORT = -10;
    public static final int ARGON2_SECRET_TOO_LONG = -11;

    public static final int ARGON2_TIME_TOO_SMALL = -12;
    public static final int ARGON2_TIME_TOO_LARGE = -13;

    public static final int ARGON2_MEMORY_TOO_LITTLE = -14;
    public static final int ARGON2_MEMORY_TOO_MUCH = -15;

    public static final int ARGON2_LANES_TOO_FEW = -16;
    public static final int ARGON2_LANES_TOO_MANY = -17;

    public static final int ARGON2_PWD_PTR_MISMATCH = -18;    /* NULL ptr with non-zero length */
    public static final int ARGON2_SALT_PTR_MISMATCH = -19;   /* NULL ptr with non-zero length */
    public static final int ARGON2_SECRET_PTR_MISMATCH = -20; /* NULL ptr with non-zero length */
    public static final int ARGON2_AD_PTR_MISMATCH = -21;     /* NULL ptr with non-zero length */

    public static final int ARGON2_MEMORY_ALLOCATION_ERROR = -22;

    public static final int ARGON2_FREE_MEMORY_CBK_NULL = -23;
    public static final int ARGON2_ALLOCATE_MEMORY_CBK_NULL = -24;

    public static final int ARGON2_INCORRECT_PARAMETER = -25;
    public static final int ARGON2_INCORRECT_TYPE = -26;

    public static final int ARGON2_OUT_PTR_MISMATCH = -27;

    public static final int ARGON2_THREADS_TOO_FEW = -28;
    public static final int ARGON2_THREADS_TOO_MANY = -29;

    public static final int ARGON2_MISSING_ARGS = -30;

    public static final int ARGON2_ENCODING_FAIL = -31;

    public static final int ARGON2_DECODING_FAIL = -32;

    public static final int ARGON2_THREAD_FAIL = -33;

    public static final int ARGON2_DECODING_LENGTH_FAIL = -34;

    public static final int ARGON2_VERIFY_MISMATCH = -35;
}
