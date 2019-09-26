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
public class Definitions
{
    public static final int T_COST_DEF = 3;
    public static final int LOG_M_COST_DEF = 12;
    public static final int LANES_DEF  = 1;
    public static final int THREADS_DEF  = 1;
    public static final int OUTLEN_DEF = 32;
    public static final int MAX_PASS_LEN = 128;

    public static final int Argon2_d = 0;
    public static final int Argon2_i = 1;
    public static final int Argon2_id = 2;

    public static final int ARGON2_VERSION_10 = 0x10;
    public static final int ARGON2_VERSION_13 = 0x13;
    public static final int ARGON2_VERSION_NUMBER = ARGON2_VERSION_13;
}
