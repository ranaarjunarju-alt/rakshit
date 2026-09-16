#!/usr/bin/env python3
"""
build_logger.py — emit classes2.dex embedding the runtime logger.

  com.tf.lab.RTLog            single-file logger (/sdcard/runtime_logs.txt,
                              fallback: app-specific external dir), crash
                              capture, TrafficStats poller, Room DB probe
  com.tf.lab.RTLogProvider    ContentProvider instantiated by Android BEFORE
                              Application.onCreate -> logging from process start
  com.tf.lab.RTLog$CrashH     Thread.UncaughtExceptionHandler

No Frida, no root, no xposed. Validated with androguard after emission.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dex_core import Dex, Asm
from dex_emit import Emitter

JL = 'Ljava/lang/'
O = JL + 'Object;'
STR = JL + 'String;'
SB = JL + 'StringBuilder;'
THREAD = JL + 'Thread;'
UEH = JL + 'Thread$UncaughtExceptionHandler;'
THROW = JL + 'Throwable;'
RUNNABLE = JL + 'Runnable;'
CTX = 'Landroid/content/Context;'
INTENT = 'Landroid/content/Intent;'
ENV = 'Landroid/os/Environment;'
FILE = 'Ljava/io/File;'
FOS = 'Ljava/io/FileOutputStream;'
OS = 'Ljava/io/OutputStream;'
SDF = 'Ljava/text/SimpleDateFormat;'
DATE = 'Ljava/util/Date;'
PM = 'Landroid/content/pm/PackageManager;'
PI = 'Landroid/content/pm/PackageInfo;'
SIG = 'Landroid/content/pm/Signature;'
AI = 'Landroid/content/pm/ApplicationInfo;'
SQLDB = 'Landroid/database/sqlite/SQLiteDatabase;'
CFAC = 'Landroid/database/sqlite/SQLiteDatabase$CursorFactory;'
CUR = 'Landroid/database/Cursor;'
TSTATS = 'Landroid/net/TrafficStats;'
PROC = 'Landroid/os/Process;'
BUILD = 'Landroid/os/Build;'
BVER = 'Landroid/os/Build$VERSION;'
LOG = 'Landroid/util/Log;'
CP = 'Landroid/content/ContentProvider;'
URI = 'Landroid/net/Uri;'
CV = 'Landroid/content/ContentValues;'
SARR = '[Ljava/lang/String;'
BARR = '[B'
SIGARR = '[Landroid/content/pm/Signature;'
R = 'Lcom/tf/lab/RTLog;'
P = 'Lcom/tf/lab/RTLogProvider;'
H = 'Lcom/tf/lab/RTLog$CrashH;'


def build():
    d = Dex()

    # ------------------------------------------------------------- fields
    F_OUT    = d.fid(R, 'OUT', STR)
    F_DDIR   = d.fid(R, 'DATA_DIR', STR)
    F_MAXLEN = d.fid(R, 'MAXLEN', 'J')
    F_PREV   = d.fid(H, 'prev', UEH)

    F_MODEL  = d.fid(BUILD, 'MODEL', STR)
    F_MANUF  = d.fid(BUILD, 'MANUFACTURER', STR)
    F_FING   = d.fid(BUILD, 'FINGERPRINT', STR)
    F_SDK    = d.fid(BVER, 'SDK_INT', 'I')
    F_VNAME  = d.fid(PI, 'versionName', STR)
    F_VCODE  = d.fid(PI, 'versionCode', 'I')
    F_SIGS   = d.fid(PI, 'signatures', SIGARR)
    F_DDIR2  = d.fid(AI, 'dataDir', STR)
    F_SDIR   = d.fid(AI, 'sourceDir', STR)

    # ------------------------------------------------------------- methods
    M_CLINIT = d.mid(R, '<clinit>', 'V', [])
    M_RTINIT = d.mid(R, '<init>', 'V', [])
    M_INIT   = d.mid(R, 'init', 'V', [CTX])
    M_BOOT   = d.mid(R, 'boot', 'V', [CTX])
    M_REQALL = d.mid(R, 'requestAllFiles', 'V', [CTX])
    M_CRASH  = d.mid(R, 'installCrashHandlers', 'V', [])
    M_LOG    = d.mid(R, 'log', 'V', [STR, STR, STR])
    M_FMTNOW = d.mid(R, 'fmtNow', STR, [])
    M_DBPROBE= d.mid(R, 'dbProbe', 'V', [])
    M_NET    = d.mid(R, 'logTraffic', 'V', [])
    M_J      = d.mid(R, 'j', STR, [SARR])

    M_OBJ_I   = d.mid(O, '<init>', 'V', [])
    M_SB_I    = d.mid(SB, '<init>', 'V', [])
    M_SB_AS   = d.mid(SB, 'append', SB, [STR])
    M_SB_AI   = d.mid(SB, 'append', SB, ['I'])
    M_SB_AJ   = d.mid(SB, 'append', SB, ['J'])
    M_SB_TS   = d.mid(SB, 'toString', STR, [])
    M_CONCAT  = d.mid(STR, 'concat', STR, [STR])
    M_GETB    = d.mid(STR, 'getBytes', BARR, [])
    M_VOF_I   = d.mid(STR, 'valueOf', STR, ['I'])
    M_FILE_I  = d.mid(FILE, '<init>', 'V', [STR])
    M_FILE_LN = d.mid(FILE, 'length', 'J', [])
    M_FILE_AB = d.mid(FILE, 'getAbsolutePath', STR, [])
    M_FILE_LS = d.mid(FILE, 'list', SARR, [])
    M_FILE_EX = d.mid(FILE, 'exists', 'Z', [])
    M_FOS_I   = d.mid(FOS, '<init>', 'V', [STR, 'Z'])
    M_OS_W    = d.mid(OS, 'write', 'V', [BARR])
    M_OS_C    = d.mid(OS, 'close', 'V', [])
    M_MILLIS  = d.mid(JL + 'System;', 'currentTimeMillis', 'J', [])
    M_DATE_I  = d.mid(DATE, '<init>', 'V', ['J'])
    M_SDF_I   = d.mid(SDF, '<init>', 'V', [STR])
    M_SDF_F   = d.mid(SDF, 'format', STR, [DATE])
    M_ENV_ST  = d.mid(ENV, 'getExternalStorageState', STR, [])
    M_ENV_MGR = d.mid(ENV, 'isExternalStorageManager', 'Z', [])
    M_CTX_PKG = d.mid(CTX, 'getPackageName', STR, [])
    M_CTX_PM  = d.mid(CTX, 'getPackageManager', PM, [])
    M_CTX_AI  = d.mid(CTX, 'getApplicationInfo', AI, [])
    M_CTX_EFD = d.mid(CTX, 'getExternalFilesDir', FILE, [STR])
    M_CTX_SA  = d.mid(CTX, 'startActivity', 'V', [INTENT])
    M_PM_PI   = d.mid(PM, 'getPackageInfo', PI, [STR, 'I'])
    M_SIG_TS  = d.mid(SIG, 'toCharsString', STR, [])
    M_TH_SL   = d.mid(THREAD, 'sleep', 'V', ['J'])
    M_TH_I    = d.mid(THREAD, '<init>', 'V', [RUNNABLE])
    M_TH_ST   = d.mid(THREAD, 'start', 'V', [])
    M_TH_SN   = d.mid(THREAD, 'setName', 'V', [STR])
    M_TH_GN   = d.mid(THREAD, 'getName', STR, [])
    M_TH_GD   = d.mid(THREAD, 'getDefaultUncaughtExceptionHandler', UEH, [])
    M_TH_SD   = d.mid(THREAD, 'setDefaultUncaughtExceptionHandler', 'V', [UEH])
    M_LOG_STK = d.mid(LOG, 'getStackTraceString', STR, [THROW])
    M_UID     = d.mid(PROC, 'myUid', 'I', [])
    M_PID     = d.mid(PROC, 'myPid', 'I', [])
    M_TS_TX   = d.mid(TSTATS, 'getUidTxBytes', 'J', ['I'])
    M_TS_RX   = d.mid(TSTATS, 'getUidRxBytes', 'J', ['I'])
    M_SQL_OP  = d.mid(SQLDB, 'openDatabase', SQLDB, [STR, CFAC, 'I'])
    M_SQL_RQ  = d.mid(SQLDB, 'rawQuery', CUR, [STR, SARR])
    M_SQL_CL  = d.mid(SQLDB, 'close', 'V', [])
    M_CUR_CN  = d.mid(CUR, 'getColumnNames', SARR, [])
    M_CUR_NX  = d.mid(CUR, 'moveToNext', 'Z', [])
    M_CUR_CC  = d.mid(CUR, 'getColumnCount', 'I', [])
    M_CUR_GS  = d.mid(CUR, 'getString', STR, ['I'])
    M_CUR_CL  = d.mid(CUR, 'close', 'V', [])
    M_INT_I   = d.mid(INTENT, '<init>', 'V', [STR])
    M_INT_AF  = d.mid(INTENT, 'addFlags', INTENT, ['I'])
    M_UEH_U   = d.mid(UEH, 'uncaughtException', 'V', [THREAD, THROW])

    M_CP_I    = d.mid(CP, '<init>', 'V', [])
    M_CP_CTX  = d.mid(CP, 'getContext', CTX, [])
    M_P_I     = d.mid(P, '<init>', 'V', [])
    M_P_CR    = d.mid(P, 'onCreate', 'Z', [])
    M_P_Q     = d.mid(P, 'query', CUR, [URI, SARR, STR, SARR, STR])
    M_P_INS   = d.mid(P, 'insert', URI, [URI, CV])
    M_P_UPD   = d.mid(P, 'update', 'I', [URI, CV, STR, SARR])
    M_P_DEL   = d.mid(P, 'delete', 'I', [URI, STR, SARR])
    M_P_TYP   = d.mid(P, 'getType', STR, [URI])
    M_P_RUN   = d.mid(P, 'run', 'V', [])
    M_H_I     = d.mid(H, '<init>', 'V', [UEH])
    M_H_U     = d.mid(H, 'uncaughtException', 'V', [THREAD, THROW])

    cm = {}

    def cstr(a, r, s):
        d.sid(s)
        a.const_string(r, s)

    def sb_new(a, r):
        a.new_instance(r, SB)
        a.inv_direct(M_SB_I, r)

    def sb_add(a, sb, tmp, s):
        cstr(a, tmp, s)
        a.inv_virtual(M_SB_AS, sb, tmp)
        a.move_result_object(sb)

    def sb_add_reg(a, sb, reg):
        a.inv_virtual(M_SB_AS, sb, reg)
        a.move_result_object(sb)

    def log3(a, r0, lvl, tag, msgreg):
        cstr(a, r0, lvl)
        cstr(a, r0 + 1, tag)
        a.inv_static(M_LOG, r0, r0 + 1, msgreg)

    def loglit(a, r0, lvl, tag, msg):
        cstr(a, r0, lvl)
        cstr(a, r0 + 1, tag)
        cstr(a, r0 + 2, msg)
        a.inv_static(M_LOG, r0, r0 + 1, r0 + 2)

    # ================================================================ RTLog
    # ---- <clinit>
    a = Asm()
    a.constw32(0, 25000000)
    a.sput_wide(0, F_MAXLEN)
    a.ret_void()
    cm[M_CLINIT] = (2, 0, 0, a)

    # ---- <init>
    a = Asm()
    a.inv_direct(M_OBJ_I, 0)
    a.ret_void()
    cm[M_RTINIT] = (1, 1, 1, a)

    # ---- log(String level, String tag, String msg)   regs 15, params @12..14
    a = Asm()
    a.L('t0')
    a.sget_object(0, F_OUT)
    a.if_eqz(0, 'end')
    a.new_instance(1, FILE)
    a.inv_direct(M_FILE_I, 1, 0)
    a.inv_virtual(M_FILE_LN, 1)
    a.move_result_wide(2)
    a.sget_wide(4, F_MAXLEN)
    a.cmp_long(6, 2, 4)                       # v6 = sign(v2/v3 - v4/v5)
    a.const4(7, 0)
    a.if_ge(6, 7, 'end')
    sb_new(a, 7)
    a.inv_static(M_FMTNOW)
    a.move_result_object(8)
    sb_add_reg(a, 7, 8)
    sb_add(a, 7, 8, ' ')
    sb_add_reg(a, 7, 12)
    sb_add(a, 7, 8, ' ')
    sb_add_reg(a, 7, 13)
    sb_add(a, 7, 8, ': ')
    sb_add_reg(a, 7, 14)
    sb_add(a, 7, 8, '\n')
    a.inv_virtual(M_SB_TS, 7)
    a.move_result_object(8)                     # line
    a.inv_virtual(M_GETB, 8)
    a.move_result_object(9)                     # bytes
    a.new_instance(10, FOS)
    a.const4(11, 1)
    a.inv_direct(M_FOS_I, 10, 0, 11)
    a.inv_virtual(M_OS_W, 10, 9)
    a.inv_virtual(M_OS_C, 10)
    a.L('end')
    a.ret_void()
    a.L('hdl')
    a.ret_void()
    a.try_catch_all('t0', 'end', 'hdl')
    cm[M_LOG] = (15, 3, 3, a)

    # ---- fmtNow()   regs 6
    a = Asm()
    a.L('t0')
    a.new_instance(0, SDF)
    cstr(a, 1, 'MM-dd HH:mm:ss.SSS')
    a.inv_direct(M_SDF_I, 0, 1)
    a.new_instance(2, DATE)
    a.inv_static(M_MILLIS)
    a.move_result_wide(3)
    a.inv_direct(M_DATE_I, 2, 3, 4)            # regs {v2, v3/v4 wide}
    a.inv_virtual(M_SDF_F, 0, 2)
    a.move_result_object(1)
    a.L('ok')
    a.ret_object(1)
    a.L('hdl')
    cstr(a, 0, '00-00 00:00:00.000')
    a.ret_object(0)
    a.try_catch_all('t0', 'ok', 'hdl')
    cm[M_FMTNOW] = (6, 0, 3, a)

    # ---- init(Context)   regs 5, ctx @v4
    a = Asm()
    a.L('t0')
    a.sget_object(0, F_OUT)
    a.if_nez(0, 'done')
    cstr(a, 0, '/sdcard/runtime_logs.txt')
    a.sget(1, F_SDK)
    a.const16(2, 30)
    a.if_lt(1, 2, 'set')
    a.inv_static(M_ENV_MGR)
    a.move_result(1)
    a.if_nez(1, 'set')
    a.const4(1, 0)
    a.inv_virtual(M_CTX_EFD, 4, 1)
    a.move_result_object(1)
    a.if_eqz(1, 'set')
    a.inv_virtual(M_FILE_AB, 1)
    a.move_result_object(0)
    cstr(a, 2, '/runtime_logs.txt')
    a.inv_virtual(M_CONCAT, 0, 2)
    a.move_result_object(0)
    a.L('set')
    a.sput_object(0, F_OUT)
    cstr(a, 1, 'log sink resolved: ')
    a.inv_virtual(M_CONCAT, 1, 0)
    a.move_result_object(1)
    log3(a, 2, 'I', 'RTLog', 1)
    a.L('done')
    a.ret_void()
    a.L('hdl')
    a.ret_void()
    a.try_catch_all('t0', 'done', 'hdl')
    cm[M_INIT] = (5, 1, 3, a)

    # ---- boot(Context)   regs 8, ctx @v7
    a = Asm()
    a.L('t0')
    log3_ = None
    cstr(a, 0, 'I'); cstr(a, 1, 'RTLog')
    cstr(a, 2, '==== TopFollow RE instrumentation boot ====')
    a.inv_static(M_LOG, 0, 1, 2)
    cstr(a, 0, 'I'); cstr(a, 1, 'BOOT')
    for lit, fld in (('model=', F_MODEL), ('manufacturer=', F_MANUF),
                     ('fingerprint=', F_FING)):
        cstr(a, 2, lit)
        a.sget_object(3, fld)
        a.inv_virtual(M_CONCAT, 2, 3)
        a.move_result_object(2)
        a.inv_static(M_LOG, 0, 1, 2)
    a.sget(2, F_SDK)
    a.inv_static(M_VOF_I, 2)
    a.move_result_object(2)
    cstr(a, 3, 'sdk=')
    a.inv_virtual(M_CONCAT, 3, 2)
    a.move_result_object(3)
    a.inv_static(M_LOG, 0, 1, 3)
    a.inv_static(M_PID)
    a.move_result(2)
    a.inv_static(M_VOF_I, 2)
    a.move_result_object(2)
    cstr(a, 3, 'pid=')
    a.inv_virtual(M_CONCAT, 3, 2)
    a.move_result_object(3)
    a.inv_static(M_LOG, 0, 1, 3)
    a.inv_virtual(M_CTX_PKG, 7)
    a.move_result_object(2)
    cstr(a, 3, 'pkg=')
    a.inv_virtual(M_CONCAT, 3, 2)
    a.move_result_object(3)
    a.inv_static(M_LOG, 0, 1, 3)
    a.inv_virtual(M_CTX_PM, 7)
    a.move_result_object(2)                    # pm
    a.inv_virtual(M_CTX_PKG, 7)
    a.move_result_object(4)                    # pkg
    a.const16(3, 64)                           # GET_SIGNATURES
    a.inv_virtual(M_PM_PI, 2, 4, 3)
    a.move_result_object(3)                    # PackageInfo
    a.iget_object(4, 3, F_VNAME)
    cstr(a, 5, 'versionName=')
    a.inv_virtual(M_CONCAT, 5, 4)
    a.move_result_object(5)
    a.inv_static(M_LOG, 0, 1, 5)
    a.iget(4, 3, F_VCODE)
    a.inv_static(M_VOF_I, 4)
    a.move_result_object(4)
    cstr(a, 5, 'versionCode=')
    a.inv_virtual(M_CONCAT, 5, 4)
    a.move_result_object(5)
    a.inv_static(M_LOG, 0, 1, 5)
    a.iget_object(4, 3, F_SIGS)
    a.if_eqz(4, 'nosig')
    a.const4(5, 0)
    a.aget_object(5, 4, 5)
    a.inv_virtual(M_SIG_TS, 5)
    a.move_result_object(5)
    cstr(a, 6, 'signer=')
    a.inv_virtual(M_CONCAT, 6, 5)
    a.move_result_object(6)
    a.inv_static(M_LOG, 0, 1, 6)
    a.L('nosig')
    a.inv_virtual(M_CTX_AI, 7)
    a.move_result_object(3)
    a.iget_object(4, 3, F_DDIR2)
    a.sput_object(4, F_DDIR)
    cstr(a, 5, 'dataDir=')
    a.inv_virtual(M_CONCAT, 5, 4)
    a.move_result_object(5)
    a.inv_static(M_LOG, 0, 1, 5)
    a.iget_object(4, 3, F_SDIR)
    cstr(a, 5, 'sourceDir=')
    a.inv_virtual(M_CONCAT, 5, 4)
    a.move_result_object(5)
    a.inv_static(M_LOG, 0, 1, 5)
    a.inv_static(M_ENV_ST)
    a.move_result_object(4)
    cstr(a, 5, 'extState=')
    a.inv_virtual(M_CONCAT, 5, 4)
    a.move_result_object(5)
    a.inv_static(M_LOG, 0, 1, 5)
    a.sget_object(4, F_OUT)
    cstr(a, 5, 'sink=')
    a.inv_virtual(M_CONCAT, 5, 4)
    a.move_result_object(5)
    a.inv_static(M_LOG, 0, 1, 5)
    a.ret_void()
    a.L('hdl')
    a.ret_void()
    a.try_catch_all('t0', 'hdl', 'hdl')
    cm[M_BOOT] = (8, 1, 3, a)

    # ---- requestAllFiles(Context)   regs 5, ctx @v4
    a = Asm()
    a.L('t0')
    a.sget(0, F_SDK)
    a.const16(1, 30)
    a.if_lt(0, 1, 'end')
    a.inv_static(M_ENV_MGR)
    a.move_result(0)
    a.if_nez(0, 'end')
    a.new_instance(0, INTENT)
    cstr(a, 1, 'android.settings.MANAGE_ALL_FILES_ACCESS_PERMISSION')
    a.inv_direct(M_INT_I, 0, 1)
    a.const32(1, 0x10000000)                   # FLAG_ACTIVITY_NEW_TASK
    a.inv_virtual(M_INT_AF, 0, 1)
    a.inv_virtual(M_CTX_SA, 4, 0)
    loglit(a, 1, 'I', 'RTLog', 'requested all-files-access (settings page opened)')
    a.L('end')
    a.ret_void()
    a.L('hdl')
    loglit(a, 0, 'W', 'RTLog', 'all-files-access request failed')
    a.ret_void()
    a.try_catch_all('t0', 'end', 'hdl')
    cm[M_REQALL] = (5, 1, 3, a)

    # ---- installCrashHandlers()   regs 3
    a = Asm()
    a.L('t0')
    a.inv_static(M_TH_GD)
    a.move_result_object(0)
    a.new_instance(1, H)
    a.inv_direct(M_H_I, 1, 0)
    a.inv_static(M_TH_SD, 1)
    loglit(a, 0, 'I', 'RTLog', 'crash handler installed')
    a.ret_void()
    a.L('hdl')
    a.ret_void()
    a.try_catch_all('t0', 'hdl', 'hdl')
    cm[M_CRASH] = (3, 0, 3, a)

    # ---- j(String[])   regs 5, arr @v4
    a = Asm()
    a.L('t0')
    a.if_eqz(4, 'lnull')
    a.array_length(0, 4)
    sb_new(a, 1)
    a.const4(2, 0)
    a.L('loop')
    a.if_ge(2, 0, 'lend')
    a.aget_object(3, 4, 2)
    sb_add_reg(a, 1, 3)
    sb_add(a, 1, 3, ' ')
    a.add_int_lit8(2, 2, 1)
    a.goto('loop')
    a.L('lend')
    a.inv_virtual(M_SB_TS, 1)
    a.move_result_object(0)
    a.L('done')
    a.ret_object(0)
    a.L('lnull')
    cstr(a, 0, '(null)')
    a.ret_object(0)
    a.L('hdl')
    cstr(a, 0, '(join-err)')
    a.ret_object(0)
    a.try_catch_all('t0', 'done', 'hdl')
    cm[M_J] = (5, 1, 2, a)

    # ---- logTraffic()   regs 6
    a = Asm()
    a.L('t0')
    a.inv_static(M_UID)
    a.move_result(0)
    a.inv_static(M_TS_TX, 0)
    a.move_result_wide(1)                       # v1,v2
    a.inv_static(M_TS_RX, 0)
    a.move_result_wide(3)                       # v3,v4
    sb_new(a, 5)
    sb_add(a, 5, 0, 'uid=')
    # v0 (uid int) was clobbered by sb_add's tmp register; recompute
    a.inv_static(M_UID)
    a.move_result(0)
    a.inv_virtual(M_SB_AI, 5, 0)
    a.move_result_object(5)
    sb_add(a, 5, 0, ' tx=')
    a.inv_virtual(M_SB_AJ, 5, 1, 2)            # wide pair v1/v2
    a.move_result_object(5)
    sb_add(a, 5, 0, ' rx=')
    a.inv_virtual(M_SB_AJ, 5, 3, 4)            # wide pair v3/v4
    a.move_result_object(5)
    a.inv_virtual(M_SB_TS, 5)
    a.move_result_object(0)
    log3(a, 1, 'I', 'NET', 0)
    a.ret_void()
    a.L('hdl')
    a.ret_void()
    a.try_catch_all('t0', 'hdl', 'hdl')
    cm[M_NET] = (6, 0, 3, a)

    # ---- dbProbe()   regs 12
    a = Asm()
    a.L('t0')
    a.sget_object(0, F_DDIR)
    a.if_eqz(0, 'end')
    cstr(a, 1, '/databases')
    a.inv_virtual(M_CONCAT, 0, 1)
    a.move_result_object(0)                    # dbdir
    a.new_instance(1, FILE)
    a.inv_direct(M_FILE_I, 1, 0)
    a.inv_virtual(M_FILE_EX, 1)
    a.move_result(2)
    a.if_eqz(2, 'end')
    a.inv_virtual(M_FILE_LS, 1)
    a.move_result_object(2)
    a.inv_static(M_J, 2)
    a.move_result_object(3)
    cstr(a, 4, 'db files: ')
    a.inv_virtual(M_CONCAT, 4, 3)
    a.move_result_object(4)
    cstr(a, 5, 'I'); cstr(a, 6, 'DB')
    a.inv_static(M_LOG, 5, 6, 4)
    cstr(a, 4, '/t_f_d_b_f_v_c.db')
    a.inv_virtual(M_CONCAT, 0, 4)
    a.move_result_object(4)                    # db path
    a.new_instance(5, FILE)
    a.inv_direct(M_FILE_I, 5, 4)
    a.inv_virtual(M_FILE_EX, 5)
    a.move_result(6)
    a.if_eqz(6, 'end')
    a.const4(6, 1)                             # OPEN_READONLY
    a.const4(7, 0)                             # null factory
    a.inv_static(M_SQL_OP, 4, 7, 6)
    a.move_result_object(5)                    # db
    cstr(a, 6, 'SELECT * FROM t_f_d_b_f_v_c LIMIT 5')
    a.const4(7, 0)                             # null selectionArgs
    a.inv_virtual(M_SQL_RQ, 5, 6, 7)
    a.move_result_object(6)                    # cursor
    a.inv_interface(M_CUR_CN, 6)
    a.move_result_object(7)
    a.inv_static(M_J, 7)
    a.move_result_object(8)
    cstr(a, 9, 'cols: ')
    a.inv_virtual(M_CONCAT, 9, 8)
    a.move_result_object(9)
    cstr(a, 10, 'I'); cstr(a, 11, 'DB')
    a.inv_static(M_LOG, 10, 11, 9)
    a.L('rowloop')
    a.inv_interface(M_CUR_NX, 6)
    a.move_result(7)
    a.if_eqz(7, 'rowsend')
    sb_new(a, 8)
    a.inv_interface(M_CUR_CC, 6)
    a.move_result(9)
    a.const4(10, 0)
    a.L('colloop')
    a.if_ge(10, 9, 'colend')
    a.inv_interface(M_CUR_GS, 6, 10)
    a.move_result_object(11)
    sb_add_reg(a, 8, 11)
    sb_add(a, 8, 11, ' | ')
    a.add_int_lit8(10, 10, 1)
    a.goto('colloop')
    a.L('colend')
    a.inv_virtual(M_SB_TS, 8)
    a.move_result_object(8)
    cstr(a, 9, 'row: ')
    a.inv_virtual(M_CONCAT, 9, 8)
    a.move_result_object(9)
    cstr(a, 10, 'I'); cstr(a, 11, 'DB')
    a.inv_static(M_LOG, 10, 11, 9)
    a.goto('rowloop')
    a.L('rowsend')
    a.inv_interface(M_CUR_CL, 6)
    a.inv_virtual(M_SQL_CL, 5)
    a.L('end')
    a.ret_void()
    a.L('hdl')
    loglit(a, 0, 'W', 'DB', 'probe failed')
    a.ret_void()
    a.try_catch_all('t0', 'end', 'hdl')
    cm[M_DBPROBE] = (12, 0, 3, a)

    # ===================================================== RTLogProvider
    a = Asm()
    a.inv_direct(M_CP_I, 0)
    a.ret_void()
    cm[M_P_I] = (1, 1, 1, a)

    # ---- onCreate   regs 4, this @v3
    a = Asm()
    a.L('t0')
    a.inv_virtual(M_CP_CTX, 3)
    a.move_result_object(0)
    a.inv_static(M_INIT, 0)
    a.inv_static(M_BOOT, 0)
    a.inv_static(M_REQALL, 0)
    a.inv_static(M_CRASH)
    a.new_instance(1, THREAD)
    a.inv_direct(M_TH_I, 1, 3)                 # Thread(this /* Runnable */)
    cstr(a, 2, 'RTLog-bg')
    a.inv_virtual(M_TH_SN, 1, 2)
    a.inv_virtual(M_TH_ST, 1)
    a.const4(0, 1)
    a.L('ok')
    a.ret(0)
    a.L('hdl')
    a.const4(0, 1)
    a.ret(0)
    a.try_catch_all('t0', 'ok', 'hdl')
    cm[M_P_CR] = (4, 1, 2, a)

    # ---- run   regs 4, this @v3
    a = Asm()
    loglit(a, 0, 'I', 'RTLog', 'background thread up')
    a.const4(0, 0)                             # tick counter
    a.L('loop')
    a.constw16(1, 5000)
    a.L('s0')
    a.inv_static(M_TH_SL, 1, 2)                # sleep(J): regs {v1/v2} wide
    a.L('s1')
    a.inv_static(M_NET)
    a.add_int_lit8(0, 0, 1)
    a.const16(1, 12)
    a.if_lt(0, 1, 'loop')
    a.const4(0, 0)
    a.inv_static(M_DBPROBE)
    a.goto('loop')
    a.L('lend')
    a.try_catch_all('s0', 's1', 's1')          # swallow InterruptedException
    a.try_catch_all('loop', 's0', 'loop')
    a.try_catch_all('s1', 'lend', 'loop')
    cm[M_P_RUN] = (4, 1, 3, a)

    # ---- query/insert/update/delete/getType stubs
    a = Asm(); a.const4(0, 0); a.ret_object(0)
    cm[M_P_Q] = (7, 6, 0, a)
    a = Asm(); a.const4(0, 0); a.ret_object(0)
    cm[M_P_INS] = (4, 3, 0, a)
    a = Asm(); a.const4(0, 0); a.ret(0)
    cm[M_P_UPD] = (6, 5, 0, a)
    a = Asm(); a.const4(0, 0); a.ret(0)
    cm[M_P_DEL] = (5, 4, 0, a)
    a = Asm(); a.const4(0, 0); a.ret_object(0)
    cm[M_P_TYP] = (3, 2, 0, a)

    # ===================================================== CrashH
    a = Asm()
    a.inv_direct(M_OBJ_I, 0)
    a.iput_object(1, 0, F_PREV)
    a.ret_void()
    cm[M_H_I] = (2, 2, 1, a)

    # ---- uncaughtException(Thread, Throwable)  regs 6, this v3, p0 v4, p1 v5
    a = Asm()
    a.L('t0')
    cstr(a, 0, 'FATAL')
    sb_new(a, 1)
    sb_add(a, 1, 2, 'uncaught on thread=')
    a.inv_virtual(M_TH_GN, 4)
    a.move_result_object(2)
    sb_add_reg(a, 1, 2)
    sb_add(a, 1, 2, ' :: ')
    a.inv_static(M_LOG_STK, 5)
    a.move_result_object(2)
    sb_add_reg(a, 1, 2)
    a.inv_virtual(M_SB_TS, 1)
    a.move_result_object(1)
    cstr(a, 2, 'CRASH')
    a.inv_static(M_LOG, 0, 2, 1)
    a.L('chain')
    a.iget_object(0, 3, F_PREV)
    a.if_eqz(0, 'end')
    a.inv_interface(M_UEH_U, 0, 4, 5)
    a.L('end')
    a.ret_void()
    a.L('hdl')
    a.goto('chain')
    a.try_catch_all('t0', 'chain', 'hdl')
    cm[M_H_U] = (6, 3, 3, a)

    # ===================================================== classes
    d.add_class(R, 0x21, O, [],
                statics=[(F_OUT, 0x9), (F_DDIR, 0x9), (F_MAXLEN, 0x9)],
                instances=[],
                directs=[(M_CLINIT, 0x10008), (M_RTINIT, 0x10001),
                         (M_INIT, 0x9), (M_BOOT, 0x9), (M_REQALL, 0x9),
                         (M_CRASH, 0x9), (M_LOG, 0x9), (M_FMTNOW, 0x9),
                         (M_DBPROBE, 0x9), (M_NET, 0x9), (M_J, 0x9)],
                virtuals=[])
    d.add_class(P, 0x21, CP, [RUNNABLE],
                statics=[], instances=[],
                directs=[(M_P_I, 0x10001)],
                virtuals=[(M_P_CR, 0x1), (M_P_Q, 0x1), (M_P_INS, 0x1),
                          (M_P_UPD, 0x1), (M_P_DEL, 0x1), (M_P_TYP, 0x1),
                          (M_P_RUN, 0x1)])
    d.add_class(H, 0x21, O, [UEH],
                statics=[], instances=[(F_PREV, 0x2)],
                directs=[(M_H_I, 0x10001)],
                virtuals=[(M_H_U, 0x1)])
    return d, cm


if __name__ == '__main__':
    d, cm = build()
    out = Emitter(d, cm).emit()
    dst = sys.argv[1] if len(sys.argv) > 1 else 'work/repack/classes2.dex'
    open(dst, 'wb').write(out)
    print('wrote', dst, len(out), 'bytes')
