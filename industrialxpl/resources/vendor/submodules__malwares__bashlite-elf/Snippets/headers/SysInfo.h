char *getArch() {
    #if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
    #elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86) || defined(__i486__) || defined(__i586__) || defined(__i686__)
    return "x86_32";
    #elif defined(__ARM_ARCH_2__)
    return "Arm2";
    #elif defined(__ARM_ARCH_3__) || defined(__ARM_ARCH_3M__)
    return "Arm3";
    #elif defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
    return "Arm4T";
    #elif defined(__ARM_ARCH_5__) || defined(__ARM_ARCH_5E__)
    return "Arm5";
    #elif defined(__ARM_ARCH_5T__) || defined(__ARM_ARCH_5TE__) || defined(__ARM_ARCH_5TEJ__)
    return "Arm5T";
    #elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__)
    return "Arm6";
    #elif defined(__ARM_ARCH_6T2__)
    return "Arm6T2";
    #elif defined(__aarch64__)
    return "ARM64";
    #elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    return "Arm7";
    #elif defined(__bfn) || defined(__DFIN__)
    return "BlackFin";
    #elif defined(__convex__)
    return "Convex";
    #elif defined(__epiphany__)
    return "Epiphany";
    #elif defined(__hppa__) || defined(__HPPA__) || defined(__hppa)
    return "HP/PA RISC";
    #elif defined (__ia64__) || defined(_IA64) || defined(__IA64__)
    return "Intel Itanium (IA-64)";
    #elif defined(__370__) || defined(__THW_370__)
    return "SystemZ";
    #elif defined(_TMS320C2XX) || defined(__TMS320C2000__)
    return "TSM320";
    #elif defined(__TSM470__)
    return "TMS470";
    #elif defined(mips) || defined(__mips__) || defined(__mips)
    return "Mips";
    #elif defined(mipsel) || defined (__mipsel__) || defined (__mipsel) || defined (_mipsel)
    return "Mipsel";
    #elif defined(__sh__)
    return "Sh4";
    #elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__ppc64__) || defined(__PPC__) || defined(__PPC64__) || defined(_ARCH_PPC) || defined(_ARCH_PPC64)
    return "Ppc";
    #elif defined(__sparc__) || defined(__sparc)
    return "spc";
    #elif defined(__m68k__)
    return "M68k";
    #elif defined(__arc__)
    return "Arc";
    #else
    return "Unknown Architecture";
    #endif
}

char *getDistro()
{
        if(access("/usr/bin/apt-get", F_OK) != -1){
        return "Ubuntu/Debian";
        }
        if(access("/usr/lib/portage", F_OK) != -1){
        return "Gentoo";
        }
        if(access("/usr/bin/yum", F_OK) != -1){
        return "REHL/Centos";
        }
        if(access("/var/lib/YaST2", F_OK) != -1){
        return "Open Suse";
        } else {
        return "Unknown Distro";
        }
}
char *getSys() 
{
    #if defined(__gnu_linux__) || defined(__linux__) || defined(linux) || defined(__linux)
    return "Linux";
    #elif defined(_WIN32)
    return "Windows (32)";
    #elif defined(_WIN64)
    return "Windows (64)";
    #elif defined(_TARGET_OS_EMBEDDED)
    return "iOS Embedded";
    #elif defined(TARGET_IPHONE_SIMULATOR)
    return "iOS Simulator";
    #elif defined(TARGED_OS_IPHONE)
    return "iPhone";
    #elif defined(TARGET_OS_MAC)
    return "Mac";
    #elif defined(_ANDROID_)
    return "Android";
    #elif defined(__sun)
    return "Solaris";
    #elif defined(__hpux)
    return "HPUX";
    #elif defined(__DragonFly__)
    return "DragonFly-BSD";
    #elif defined(__FreeBSD__)
    return "Free-BSD";
    #elif defined(__NetBSD__)
    return "Net-BSD";
    #elif defined(__OpenBSD__)
    return "Open-BSD";
    #elif defined(__unix__)
    return "Other UNIX OS";
    else
    return "Unidentified OS";
    #endif
}
