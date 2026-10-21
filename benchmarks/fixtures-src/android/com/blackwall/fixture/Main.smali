.class public Lcom/blackwall/fixture/Main;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static marker()Ljava/lang/String;
    .locals 1
    const-string v0, "BLACKWALL_INERT_APK_FIXTURE"
    return-object v0
.end method

.method public static endpoint()Ljava/lang/String;
    .locals 1
    const-string v0, "https://apk.fixture.invalid/api"
    return-object v0
.end method

.method public static configuration()Ljava/lang/String;
    .locals 1
    const-string v0, "campaign=apk-inert"
    return-object v0
.end method
