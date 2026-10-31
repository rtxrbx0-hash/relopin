
.class public L__PACKAGE__/__CLASSNAME__;
.super Ljava/lang/Object;
.source "__CLASSNAME__.java"

.field private static final BUILD_SEED:[B

.field private static final DEVICE_SALT:[B

.field private static cachedKey:[B

.method static constructor <clinit>()V
    .registers 1
    __SEED_BYTES_INIT__
    sput-object v0, L__PACKAGE__/__CLASSNAME__;->BUILD_SEED:[B

    __SALT_BYTES_INIT__
    sput-object v0, L__PACKAGE__/__CLASSNAME__;->DEVICE_SALT:[B

    const/4 v0, 0x0
    sput-object v0, L__PACKAGE__/__CLASSNAME__;->cachedKey:[B
    return-void
.end method

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method private static deviceSalt()[B
    .registers 1
    sget-object v0, L__PACKAGE__/__CLASSNAME__;->DEVICE_SALT:[B
    return-object v0
.end method

.method public static environmentFingerprint()Ljava/lang/String;
    .registers 3
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v1, Landroid/os/Build;->FINGERPRINT:Ljava/lang/String;
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0

    const-string v1, "|"
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0

    sget-object v1, Landroid/os/Build;->MODEL:Ljava/lang/String;
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0

    const-string v1, "|"
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0

    sget-object v1, Landroid/os/Build;->ID:Ljava/lang/String;
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method

.method private static sha256Concat([B[B)[B
    .registers 7
    const-string v0, "SHA-256"
    invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
    move-result-object v0

    invoke-virtual {v0, p0}, Ljava/security/MessageDigest;->update([B)V
    invoke-virtual {v0, p1}, Ljava/security/MessageDigest;->update([B)V
    invoke-virtual {v0}, Ljava/security/MessageDigest;->digest()[B
    move-result-object v0
    return-object v0
.end method

.method public static getKey()[B
    .registers 3
    sget-object v0, L__PACKAGE__/__CLASSNAME__;->cachedKey:[B
    if-eqz v0, :needDerive
    return-object v0

    :needDerive
    sget-object v0, L__PACKAGE__/__CLASSNAME__;->BUILD_SEED:[B
    invoke-static {}, L__PACKAGE__/__CLASSNAME__;->deviceSalt()[B
    move-result-object v1
    invoke-static {v0, v1}, L__PACKAGE__/__CLASSNAME__;->sha256Concat([B[B)[B
    move-result-object v2
    sput-object v2, L__PACKAGE__/__CLASSNAME__;->cachedKey:[B
    return-object v2
.end method

.method public static decrypt([B)Ljava/lang/String;
    .registers 12
    invoke-static {}, L__PACKAGE__/__CLASSNAME__;->getKey()[B
    move-result-object v0

    array-length v1, p0
    new-array v2, v1, [B      # v2 = output buffer

    const/4 v3, 0x0           # v3 = counter (int)
    const/4 v4, 0x0           # v4 = i (index in data)
    const/4 v5, 0x0           # v5 = pos in current block
    const/4 v6, 0x0           # v6 = current block ([B), null حتى أول تكرار

    :loop
    if-ge v4, v1, :done

    if-nez v6, :haveBlock
    goto :genBlock
    :haveBlock
    array-length v7, v6
    if-ne v5, v7, :useBlock
    :genBlock
    invoke-static {v3}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;
    move-result-object v7
    invoke-virtual {v7}, Ljava/lang/String;->getBytes()[B
    move-result-object v7
    invoke-static {v0, v7}, L__PACKAGE__/__CLASSNAME__;->sha256Concat([B[B)[B
    move-result-object v6
    const/4 v5, 0x0
    add-int/lit8 v3, v3, 0x1

    :useBlock
    aget-byte v7, p0, v4
    aget-byte v8, v6, v5
    xor-int/2addr v7, v8
    int-to-byte v7, v7
    aput-byte v7, v2, v4

    add-int/lit8 v4, v4, 0x1
    add-int/lit8 v5, v5, 0x1
    goto :loop

    :done
    new-instance v9, Ljava/lang/String;
    const-string v10, "UTF-8"
    invoke-direct {v9, v2, v10}, Ljava/lang/String;-><init>([BLjava/lang/String;)V
    return-object v9
.end method
