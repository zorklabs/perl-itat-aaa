FreeRADIUS rlm_perl AAA module
==============================

## Introduction
This is simple perl based module for authentication, authorization, and accounting not as general as it should be but this is not last version.

Particular vesion only authorize users by mac address, option82 and s-vlan/c-vlan is not used.

## Getting started
You should configure global variables first and services names. Maybe remove code that you will not use.

To prevent empty Event-Timestamp you should convert timestamp to integer value before activating perl module:
```
accounting {
    update control {
        &Tmp-Integer-0 := "%{integer: request:Event-Timestamp}"
    }
    perl
}
```

## TODO
1. Make module more generic
2. Add option82 and s-vlan/c-vlan authentication
