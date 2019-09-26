/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.rlsecurity.modules.argon2.model.domain;

import com.rlsecurity.modules.argon2.model.service.interfaces.IAllocateMethod;
import com.rlsecurity.modules.argon2.model.service.interfaces.IDeallocateMethod;

/**
 *
 * @author Paul G. Allen <pgallen@gmail.com>
 */
public class Context
{
    byte[] out;    /* output array */
    int outlen; /* digest length */

    byte[] pwd;    /* password array */
    int pwdlen; /* password length */

    byte[] salt;    /* salt array */
    int saltlen; /* salt length */

    byte[] secret;    /* key array */
    int secretlen; /* key length */

    byte[] ad;    /* associated data array */
    int adlen; /* associated data length */

    int t_cost;  /* number of passes */
    int m_cost;  /* amount of memory requested (KB) */
    int lanes;   /* number of lanes */
    int threads; /* maximum number of threads */

    int version; /* version number */

    public IAllocateMethod allocate_cbk; /* pointer to memory allocator */
    public IDeallocateMethod free_cbk;   /* pointer to memory deallocator */

    int flags; /* array of bool options */
}
