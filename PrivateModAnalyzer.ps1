[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Clear-Host

Write-Host "Mecz Mod Analyzer (Lite)" -ForegroundColor Gray
Write-Host

Write-Host "Path to mods folder (Enter for default): " -NoNewline
 $modsPath = Read-Host

if ([string]::IsNullOrWhiteSpace($modsPath)) {
    $modsPath = "$env:USERPROFILE\AppData\Roaming\.minecraft\mods"
}

if (-not (Test-Path $modsPath -PathType Container)) {
    Write-Host "Invalid path: $modsPath" -ForegroundColor Red
    exit 1
}

Write-Host "Scanning: $modsPath..." -ForegroundColor Cyan

function Get-FileSHA1 {
    param([string]$Path)
    return (Get-FileHash -Path $Path -Algorithm SHA1).Hash
}

function Get-DownloadSource {
    param([string]$Path)
    $zoneData = (Get-Content -Stream Zone.Identifier -LiteralPath $Path -ErrorAction SilentlyContinue) -join "`n"
    if ($zoneData -match "HostUrl=(.+)") {
        $url = $matches[1].Trim()
        
        if ($url -match "novaclient\.lol|api\.novaclient|nova\.client") { return "NovaClient (Suspicious)" }
        elseif ($url -match "dqrkis|dqrk") { return "DQRKIS (Suspicious)" }
        elseif ($url -match "vape\.gg|vapeclient|vape-client") { return "Vape (Client)" }
        elseif ($url -match "rise\.today|riseclient") { return "Rise (Client)" }
        elseif ($url -match "meteordevelopment|meteor-client") { return "Meteor (Client)" }
        elseif ($url -match "liquidbounce|liquid-bounce") { return "LiquidBounce (Client)" }
        elseif ($url -match "wurst-client|wurstmc\.net") { return "Wurst (Client)" }
        elseif ($url -match "futureclient|future-client") { return "Future (Client)" }
        elseif ($url -match "doomsdayclient") { return "DoomsdayClient" }
        elseif ($url -match "198macros") { return "198Macros" }
        elseif ($url -match "mediafire\.com") { return "MediaFire" }
        elseif ($url -match "discord\.com|discordapp\.com") { return "Discord" }
        elseif ($url -match "dropbox\.com") { return "Dropbox" }
        elseif ($url -match "drive\.google\.com") { return "Google Drive" }
        elseif ($url -match "mega\.nz|mega\.co\.nz") { return "MEGA" }
        elseif ($url -match "github\.com") { return "GitHub" }
        elseif ($url -match "modrinth\.com") { return "Modrinth" }
        elseif ($url -match "curseforge\.com") { return "CurseForge" }
        else {
            if ($url -match "https?://(?:www\.)?([^/]+)") { return $matches[1] }
            return $url
        }
    }
    return $null
}

function Query-Modrinth {
    param([string]$Hash)
    try {
        $versionInfo = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/version_file/$Hash" -Method Get -UseBasicParsing -ErrorAction Stop
        if ($versionInfo.project_id) {
            $projectInfo = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$($versionInfo.project_id)" -Method Get -UseBasicParsing -ErrorAction Stop
            return @{ Name = $projectInfo.title; Slug = $projectInfo.slug }
        }
    } catch {}
    return @{ Name = ""; Slug = "" }
}

function Query-Megabase {
    param([string]$Hash)
    try {
        $result = Invoke-RestMethod -Uri "https://megabase.vercel.app/api/query?hash=$Hash" -Method Get -UseBasicParsing -ErrorAction Stop
        if (-not $result.error) { return $result.data }
    } catch {}
    return $null
}

function Search-CoordmodClass {
    param([string]$Path)
    $targetEntry = "com/example/coordmod/compact/a/a/e/c/BlockC.class"
    $patterns = @(
        "FINDING_SPAWNER","OPENING_SPAWNER","WAITING_SPAWNER_GUI","LOOTING_BONES","CLOSING_SPAWNER",
        "ORDER_COMMAND","WAIT_ORDER_GUI","SELECT_ORDER_ITEM","WAIT_DELIVERY_GUI","DELIVERING_BONES",
        "WAIT_AFTER_DELIVERY_1","CLOSING_DELIVERY","WAIT_AFTER_CLOSE_DELIVERY","WAIT_CONFIRM_GUI","WAIT_CONFIRM_SETTLE",
        "CLICK_CONFIRM_SLOT","WAIT_AFTER_CONFIRM_1","WAIT_AFTER_CONFIRM_2","WAIT_AFTER_CONFIRM_3",
        "DOUBLE_ESCAPE","DOUBLE_RIGHTCLICK_FIRST","DOUBLE_RIGHTCLICK_SECOND","POST_CYCLE_DELAY",
        "mace_swap","quick_strike","loot_yeeter","auto_jump_reset","macro_198",
        "stun_slam","safe_anchor","double_anchor","auto_pot_refill","totem_offhand",
        "walksy_optimizer","key_pearl","aim_assist","auto_neth_pot","auto_dtap",
        "bottle_throw","trigger_bot","auto_web",
        "SHOP_END","SHOP_ITEM","SHOP_GLASS_PANE","SHOP_BUY",
        "SHOP_CONFIRM","SHOP_CHECK_FULL","SHOP_EXIT",
        "TARGET_ORDERS","ORDERS_SELECT","ORDERS_EXIT","ORDERS_CONFIRM","ORDERS_FINAL_EXIT","CYCLE_PAUSE",
        "PLACE_OBI","WAIT_OBI","PLACE_CRYSTAL","BREAK_CRYSTAL",
        "ROTATING_DOWN","ROTATING_BACK","REFILLING",
        "PLANTING","BONEMEALING"
    )
    $result = @{ EntryFound = $false; Matches = @() }
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
        $entry = $archive.Entries | Where-Object { $_.FullName -eq $targetEntry } | Select-Object -First 1
        if (-not $entry) {
            $entry = $archive.Entries | Where-Object { $_.FullName -like "*coordmod*BlockC*" } | Select-Object -First 1
        }
        if ($entry) {
            $result.EntryFound = $true
            $stream = $entry.Open()
            $ms = New-Object System.IO.MemoryStream
            $stream.CopyTo($ms)
            $bytes = $ms.ToArray()
            $ms.Dispose()
            $stream.Dispose()
            $content = [System.Text.Encoding]::GetEncoding(28591).GetString($bytes)
            foreach ($p in $patterns) {
                if ($content.IndexOf($p, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $result.Matches += $p
                }
            }
        }
        $archive.Dispose()
    } catch {}
    return $result
}

 $suspiciousPatterns = @(
    "AimAssist","AutoAnchor","AutoCrystal","AutoDoubleHand","AutoHitCrystal","AutoPot","AutoTotem","AutoArmor","InventoryTotem",
    "JumpReset","LegitTotem","PingSpoof","SelfDestruct","ShieldBreaker","TriggerBot","AxeSpam","WebMacro",
    "WalskyOptimizer","WalksyOptimizer","walsky.optimizer","WalksyCrystalOptimizerMod","Donut","Replace Mod",
    "ShieldDisabler","SilentAim","Totem Hit","Wtap","FakeLag","BlockESP","dev.krypton","Virgin","AntiMissClick",
    "LagReach","PopSwitch","SprintReset","ChestSteal","AntiBot","AirAnchor","FakeInv","HoverTotem","AutoClicker",
    "PackSpoof","Antiknockback","catlean","Argon","AuthBypass","Asteria","Prestige","MaceSwap","DoubleAnchor",
    "AutoTPA","BaseFinder","Xenon","gypsy","imgui","imgui.gl3","imgui.glfw","BowAim","Criticals","Fakenick",
    "FakeItem","invsee","ItemExploit","Hellion","hellion","LicenseCheckMixin","obfuscatedAuth","phantom-refmap.json","xyz.greaj",
    "じ.class","ふ.class","ぶ.class","ぷ.class","た.class","ね.class","そ.class","な.class","ど.class","ぐ.class",
    "ず.class","で.class","つ.class","べ.class","せ.class","と.class","み.class","び.class","す.class","の.class",
    "org.chainlibs.module.impl.modules.Crystal.Y","org.chainlibs.module.impl.modules.Crystal.bF",
    "org.chainlibs.module.impl.modules.Crystal.bM","org.chainlibs.module.impl.modules.Crystal.bY",
    "org.chainlibs.module.impl.modules.Crystal.bq","org.chainlibs.module.impl.modules.Crystal.cv",
    "org.chainlibs.module.impl.modules.Crystal.o","org.chainlibs.module.impl.modules.Blatant.I",
    "org.chainlibs.module.impl.modules.Blatant.bR","org.chainlibs.module.impl.modules.Blatant.bx",
    "org.chainlibs.module.impl.modules.Blatant.cj","org.chainlibs.module.impl.modules.Blatant.dk",
    "AutoCrystal","autocrystal","auto crystal","cw crystal","dontPlaceCrystal","dontBreakCrystal",
    "AutoHitCrystal","autohitcrystal","canPlaceCrystalServer","healPotSlot",
    "AutoAnchor","autoanchor","auto anchor","DoubleAnchor","hasGlowstone","HasAnchor",
    "anchortweaks","anchor macro","safe anchor","safeanchor","SafeAnchor","AirAnchor","anchorMacro",
    "AutoTotem","autototem","auto totem","InventoryTotem","inventorytotem","HoverTotem","hover totem","legittotem",
    "AutoPot","autopot","auto pot","speedPotSlot","strengthPotSlot","AutoArmor","autoarmor","auto armor","AutoPotRefill",
    "preventSwordBlockBreaking","preventSwordBlockAttack","ShieldDisabler","ShieldBreaker","Breaking shield with axe...",
    "AutoDoubleHand","autodoublehand","auto double hand","Failed to switch to mace after axe!",
    "AutoMace","MaceSwap","SpearSwap","StunSlam","JumpReset","axespam","axe spam",
    "EndCrystalItemMixin","findKnockbackSword","attackRegisteredThisClick",
    "AimAssist","aimassist","aim assist","triggerbot","trigger bot","Silent Rotations","SilentRotations",
    "FakeInv","swapBackToOriginalSlot","FakeLag","fakePunch","Fake Punch",
    "webmacro","web macro","AntiWeb","AutoWeb","lvstrng","dqrkis",
    "WalksyCrystalOptimizerMod","WalksyOptimizer","WalskyOptimizer","autoCrystalPlaceClock",
    "AutoFirework","ElytraSwap","FastXP","FastExp","NoJumpDelay",
    "PackSpoof","Antiknockback","catlean","AuthBypass","obfuscatedAuth","LicenseCheckMixin",
    "BaseFinder","ItemExploit","FreezePlayer","LWFH Crystal","KeyPearl","LootYeeter","FastPlace","AutoBreach",
    "setBlockBreakingCooldown","getBlockBreakingCooldown","blockBreakingCooldown",
    "onBlockBreaking","setItemUseCooldown","setSelectedSlot","invokeDoAttack","invokeDoItemUse","invokeOnMouseButton",
    "onPushOutOfBlocks","onIsGlowing","Automatically switches to sword when hitting with totem",
    "arrayOfString","POT_CHEATS","Dqrkis Client","Entity.isGlowing","Activate Key","Click Simulation","On RMB",
    "No Count Glitch","No Bounce","NoBounce","Place Delay","Break Delay","Fast Mode","Place Chance",
    "Break Chance","Stop On Kill","damagetick","Anti Weakness","Particle Chance","Trigger Key",
    "Switch Delay","Totem Slot","Smooth Rotations","Use Easing","Easing Strength","While Use",
    "Glowstone Delay","Glowstone Chance","Explode Delay","Explode Chance","Explode Slot","Only Charge",
    "Anchor Macro","Reach Distance","Min Height","Min Fall Speed","Attack Delay","Breach Delay",
    "Require Elytra","Auto Switch Back","Check Line of Sight","Only When Falling","Require Crit",
    "Show Status Display","Stop On Crystal","Check Shield","On Pop","Check Players","Predict Crystals",
    "Check Aim","Check Items","Activates Above","Blatant","Force Totem","Stay Open For",
    "Auto Inventory Totem","Only On Pop","Vertical Speed","Hover Totem","Swap Speed","Strict One-Tick",
    "Mace Priority","Min Totems","Min Pearls","Totem First","Drop Interval","Random Pattern","Loot Yeeter",
    "Horizontal Aim Speed","Vertical Aim Speed","Include Head","Web Delay","Holding Web",
    "Not When Affects Player","Hit Delay","Require Hold Axe","placeInterval","breakInterval","stopOnKill",
    "activateOnRightClick","holdCrystal","Macro Key",
    "KillAura","ClickAura","MultiAura","ForceField","LegitAura","FINDING_SPAWNER","OPENING_SPAWNER","AimBot","AutoAim","SilentAim","AimLock","HeadSnap",
    "WAITING_SPAWNER_GUI","LOOTING_BONES","CLOSING_SPAWNER","ORDER_COMMAND","WAIT_ORDER_GUI",
    "SELECT_ORDER_ITEM","WAIT_DELIVERY_GUI","DELIVERING_BONES","WAIT_AFTER_DELIVERY_1",
    "CLOSING_DELIVERY","WAIT_AFTER_CLOSE_DELIVERY","WAIT_CONFIRM_GUI","WAIT_CONFIRM_SETTLE",
    "CLICK_CONFIRM_SLOT","WAIT_AFTER_CONFIRM_1","WAIT_AFTER_CONFIRM_2","WAIT_AFTER_CONFIRM_3",
    "DOUBLE_ESCAPE","DOUBLE_RIGHTCLICK_FIRST","DOUBLE_RIGHTCLICK_SECOND","POST_CYCLE_DELAY",
    "CrystalAura","AnchorAura","AnchorFill","AnchorPlace","BedAura","AutoBed","BedBomb","BedPlace",
    "BowAimbot","BowSpam","AutoBow","AutoCrit","CritBypass","AlwaysCrit","CriticalHit",
    "ReachHack","ExtendReach","LongReach","HitboxExpand","AntiKB","NoKnockback","GrimVelocity","GrimDisabler",
    "VelocitySpoof","KBReduce","OffhandTotem","TotemSwitch","AutoWeapon","AutoSword","AutoCity","Burrow","SelfTrap",
    "HoleFiller","AntiSurround","AntiBurrow","WTap","TargetStrafe","AutoGap","AutoPearl",
    "FlyHack","CreativeFlight","BoatFly","PacketFly","AirJump","SpeedHack","BHop","BunnyHop",
    "AntiFall","NoFallDamage","StepHack","FastClimb","AutoStep","HighStep","WaterWalk","LiquidWalk","LavaWalk",
    "NoSlow","NoSlowdown","NoWeb","NoSoulSand","WallHack","ElytraSpeed","InstantElytra",
    "ScaffoldWalk","FastBridge","AutoBridge","Nuker","NukerLegit","InstantBreak","GhostHand","NoSwing",
    "PlaceAssist","AirPlace","AutoPlace","InstantPlace","PlayerESP","MobESP","ItemESP","StorageESP","ChestESP",
    "Tracers","NameTagsHack","XRayHack","OreFinder","CaveFinder","OreESP","NewChunks","TunnelFinder",
    "TargetHUD","ReachDisplay","DoubleClicker","JitterClick","ButterflyClick","CPSBoost",
    "ChestStealer","InvManager","InvMovebypass","AutoSprint","AntiAFK","FakeLatency","FakePing",
    "SpoofRotation","PositionSpoof","GameSpeed","SpeedTimer",
    "GrimBypass","VulcanBypass","MatrixBypass","AACBypass","VerusDisabler","IntaveBypass","WatchdogBypass",
    "PacketMine","PacketWalk","PacketSneak","PacketCancel","PacketDupe","PacketSpam",
    "SelfDestruct","HideClient","SessionStealer","TokenLogger","TokenGrabber","DiscordToken",
    "ReverseShell","C2Server","KeyLogger","StashFinder","TrailFinder",
    "imgui.binding","imgui.gl3","imgui.glfw","JNativeHook","GlobalScreen","NativeKeyListener",
    "client-refmap.json","cheat-refmap.json","phantom-refmap.json",
    "aHR0cDovL2FwaS5ub3ZhY2xpZW50LmxvbC93ZWJob29rLnR4dA==",
    "meteordevelopment","cc/novoline","com/alan/clients","club/maxstats","wtf/moonlight",
    "me/zeroeightsix/kami","net/ccbluex","today/opai","net/minecraft/injection",
    "org/chainlibs/module/impl/modules","xyz/greaj","com/cheatbreaker",
    "doomsdayclient","DoomsdayClient","doomsday.jar","novaclient","api.novaclient.lol",
    "WalksyOptimizer","vape.gg","vapeclient","VapeClient","VapeLite","intent.store","IntentClient",
    "rise.today","riseclient.com","meteor-client","meteorclient","meteordevelopment.meteorclient",
    "liquidbounce","fdp-client","net.ccbluex","novoware","novoclient","aristois","impactclient","azura",
    "pandaware","moonClient","astolfo","futureClient","konas","rusherhack","inertia","exhibition",
    "sessionstealer","tokengrabber","webhookstealer","cookiethief","discordstealer","keylogger",
    "iplogger","cryptominer","reverseShell","backdoormod","exploitmod","ratmod","ransomware",
    "sendWebhook","exfiltrate","connectBack","callHome","grabToken","stealSession","accountstealer",
    "discord/token","grabber/cookie","grab_cookies","stealerutils","sendToWebhook","postDiscord",
    "webhookurl","discordwebhook",
    "crasher","lagmachine","booksploit","signcrasher","entityspammer","nukermod","worldnuker",
    "tntmod","bedexplode","anchorexplode","injectClass","modifyBytecode","hookMethod",
    "attachAgent","VirtualMachine.attach",
    "FLOW_OBFUSCATION","STRING_ENCRYPTION","RESOURCE_ENCRYPTION",
    "skidfuscator","me/itzsomebody","radon/transform","bozar/","paramorphism","zelix/klassmaster",
    "allatori","dasho","com/icqm/smoke","dev.krypton","dev.gambleclient","com.cheatbreaker",
    "spoofVersion","brandOverride","overrideBrand","fakeClientBrand","brandSpoof","versionSpoof",
    "cancelPacket","dropPacket","suppressPacket","blockPacket","spoofPacket","injectPacket",
    "sendFakePacket","sendSilentPacket","bypassAC","bypass_ac","evadeAC","evadeAnticheat",
    "isGrimAC","isNoCheat","isAAC","isSpartanAC","isIntave","grimBypass","ncpBypass","aacBypass",
    "spartanBypass","checkAnticheat","detectAnticheat","getAnticheat","GrimBypass","NCPBypass",
    "AACBypass","IntaveBypass",
    "setTimerSpeed","timerSpeed","Timer.timerSpeed","setTickRate",
    "overrideTickRate","fakeTickCount","tickBoost","hitboxExpand","expandHitbox",
    "suppressKnockback","cancelKnockback","noKnockback","setVelocity(0","zeroVelocity","ignoreKnockback",
    "antiKnockback","KnockbackModifier","noVelocity",
    "renderPlayerSpoofed","spoofRender","hideFromRender",
    "fakeGlowing","GlowBypass","glowBypass","baritone.bypass","pathfindBypass","suppressPathfind",
    "bypassLicense","fakeAuth","spoofSession","AltManager","grimac","GrimAC","grim-api","ac.grim",
    "game.grim","setGrimFlag","rotationBypass","fakeYaw","fakePitch","spoofYaw","spoofPitch","doomsday","doomsdayclient","dqrkis","dqrk",
    "vape","vapeclient","vape-client","vapelite",
    "meteor","meteorclient","meteor-client",
    "liquidbounce","liquid-bounce",
    "wurst","wurst-client",
    "futureclient","future-client",
    "konas","inertia","exhibition",
    "pandaware","astolfo","rusherhack",
    "novaclient","nova-client","novaware",
    "impactclient","aristois","azura",
    "intentclient","intentstore",
    "prestigeclient",
    "cheatbreaker","kamiblue","fdpclient",
    "skidfuscator","skidware",
    "wolframclient","wolfram-client",
    "bleachhack","bleach-hack",
    "themisclient","ravenb",
    "fluxclient","flux-client",
    "strafeclient","strafe-client",
    "FINDING_SPAWNER","OPENING_SPAWNER","WAITING_SPAWNER_GUI","LOOTING_BONES","CLOSING_SPAWNER",
    "ORDER_COMMAND","WAIT_ORDER_GUI","SELECT_ORDER_ITEM","WAIT_DELIVERY_GUI","DELIVERING_BONES",
    "WAIT_AFTER_DELIVERY_1","CLOSING_DELIVERY","WAIT_AFTER_CLOSE_DELIVERY","WAIT_CONFIRM_GUI","WAIT_CONFIRM_SETTLE",
    "CLICK_CONFIRM_SLOT","WAIT_AFTER_CONFIRM_1","WAIT_AFTER_CONFIRM_2","WAIT_AFTER_CONFIRM_3",
    "DOUBLE_ESCAPE","DOUBLE_RIGHTCLICK_FIRST","DOUBLE_RIGHTCLICK_SECOND","POST_CYCLE_DELAY",
    "mace_swap","quick_strike","loot_yeeter","auto_jump_reset","macro_198",
    "stun_slam","safe_anchor","double_anchor","auto_pot_refill","totem_offhand",
    "walksy_optimizer","key_pearl","aim_assist","auto_neth_pot","auto_dtap",
    "bottle_throw","trigger_bot","auto_web",
    "SHOP_END","SHOP_ITEM","SHOP_GLASS_PANE","SHOP_BUY",
    "SHOP_CONFIRM","SHOP_CHECK_FULL","SHOP_EXIT",
    "TARGET_ORDERS","ORDERS_SELECT","ORDERS_EXIT","ORDERS_CONFIRM","ORDERS_FINAL_EXIT","CYCLE_PAUSE",
    "PLACE_OBI","WAIT_OBI","PLACE_CRYSTAL","BREAK_CRYSTAL",
    "ROTATING_DOWN","ROTATING_BACK","REFILLING",
    "PLANTING","BONEMEALING",
    "ParseJ.a","CacheE.MISC","CacheE.RENDER","CacheE.CT",
    "CheckC","CoreH","cn`$MacroState","co`$State",
    "Ａ．ｃｔｉｖａｔｅ Ｋｅｙ","Ｃ．ｈｅｃｋ Ｐｌａｃｅ","Ｓ．ｗｉｔｃｈ Ｄｅｌａｙ","Ｓ．ｗｉｔｃｈ Ｃｈａｎｃｅ",
    "Ｐ．ｌａｃｅ Ｄｅｌａｙ","Ｐ．ｌａｃｅ Ｃｈａｎｃｅ","Ｗ．ｏｒｋ Ｗｉｔｈ Ｔｏｔｅｍ","Ｗ．ｏｒｋ Ｗｉｔｈ Ｃｒｙｓｔａｌ",
    "Ｓ．ｗｏｒｄ Ｓｗａｐ","Ａ．ｕｔｏ Ｈｉｔ Ｃｒｙｓｔａｌ","A.utomatically hit-crystals for you",
    "Ｊ．ｕｍｐ Ｒｅｓｅｔ Ｃｈａｎｃｅ","Ａ．ｕｔｏ Ｊｕｍｐ Ｒｅｓｅｔ","Ｓ．ｉｌｅｎｔ Ｒｏｔａｔｉｏｎｓ",
    "Ｈ．ｏｒｉｚｏｎｔａｌ Ａｉｍ Ｓｐｅｅｄ","Ｖ．ｅｒｔｉｃａｌ Ａｉｍ Ｓｐｅｅｄ","Ｉ．ｎｃｌｕｄｅ Ｈｅａｄ",
    "Ｗ．ｅｂ Ｄｅｌａｙ","Ｈ．ｏｌｄｉｎｇ Ｗｅｂ","Ｃ．ｌｉｃｋｉｎｇ","Ｂ．ｒｅａｋ Ｂｌｏｃｋｓ",
    "Ｎ．ｏｔ Ｗｈｅｎ Ａｆｆｅｃｔｓ Ｐｌａｙｅｒ","Ａ．ｕｔｏＷｅｂ","Ｐ．ｌａｃｅｓ Ｗｅｂｓ Ｏｎ Ｅｎｅｍｉｅｓ",
    "ｍ．ｉｎ Ｔｏｔｅｍｓ","ｍ．ｉｎ Ｐｅａｒｌｓ","ｔ．ｏｔｅｍ Ｆｉｒｓｔ","Ｄ．ｒｏｐ Ｉｎｔｅｒｖａｌ",
    "Ｒ．ａｎｄｏｍ Ｐａｔｔｅｒｎ","Ｌ．ｏｏｔ Ｙｅｅｔｅｒ","Ｒ．ｅｑｕｉｒｅ Ｓｗｏｒｄ","Ｓ．ｗｉｔｃｈ Ｂａｃｋ",
    "ａ．ｕｔｏ Ｔｏｔｅｍ Ｈｉｔ","ｐ．ｌａｃｅＩｎｔｅｒｖａｌ","ｂ．ｒｅａｋＩｎｔｅｒｖａｌ","ｓ．ｔｏｐＯｎＫｉｌｌ",
    "ａ．ｃｔｉｖａｔｅＯｎＲｉｇｈｔＣｌｉｃｋ","ｄ．ａｍａｇｅｔｉｃｋ","ｈ．ｏｌｄＣｒｙｓｔａｌ","ｆ．ａｋｅＰｕｎｃｈ",
    "Ｌ．ＷＦＨ Ｃｒｙｓｔａｌ","Ｎ．ｏ Ｓｌｏｗｄｏｗｎ","ａ．ｎｔｉ Ｗｅｂ","Ｅ．ｘｐａｎｄ Ａｍｏｕｎｔ",
    "Ｐ．ｌａｙｅｒｓ Ｏｎｌｙ","Ｉ．ｎｖｉｓｉｂｌｅｓ","ｓ．ｍａｒｔ Ｊｉｔｔｅｒ","Ｒ．ｅｎｄｅｒ Ｈｉｔｂｏｘｅｓ",
    "Ｈ．ｉｔｂｏｘｅｓ","Expands entity bounding boxes for easier targeting.",
    "Ｎ．ｏＢｏｕｎｃｅ","Ｒ．ｅｍｏｖｅｓ ｔｈｅ ｃｒｙｓｔａｌ ｂｏｕｎｃｅ ａｎｉｍａｔｉｏｎ",
    "Ｓ．ｐｒｉｎｔ","Ｋ．ｅｐｓ ｙｏｕ ｓｐｒｉｎｔｉｎｇ ａｔ ａｌｌ ｔｉｍｅｓ",
    "Ｒ．ｅｑｕｉｒｅ Ｃｌｉｃｋ","Ｖ．ｉｓｉｂｉｌｉｔｙ Ｃｈｅｃｋ","ｍ．ｉｎ Ｓｐｅｅｄ","ｍ．ａｘ Ｓｐｅｄ",
    "Ｒ．ａｎｄｏｍｉｚｅ","ａ．ｉｍ Ａｓｓｉｓｔ","ｓ．ｐｅａｒ Ｓｗａｐ","ａ．ｕｔｏ ｓｗａｐ ｔｏ ｓｐｅａｒ ｏｎ ａｔｔａｃｋ",
    "Ｐ．ｌａｃｅ Ｉｎｔｅｒｖａｌ","Ｃ．ｌｉｃｋ Ｓｉｍｕｌａｔｉｏｎ","Ｃ．ｌｉｃｋ Ｄｅｌａｙ","Ｗ．ａｌｋｓｙ Ｏｐｔｉｍｉｚｅｒ",
    "ａ．ｕｔｏ Ｐｏｔ","Ａ．ｐｐｌｙ ｇｌｏｗ ｅｆｆｅｃｔ ｔｏ ａｌｌ ｅｎｔｉｔｉｅｓ","ａ．ｓｐｅｃｔ Ｒａｔｉｏ",
    "ｍ．ａｃｅ Ｐｒｉｏｒｉｔｙ","Ｗ．ｉｎｄ","ｓ．ｗａｐ Ｓｐｅｅｄ","ｓ．ｔｒｉｃｔ Ｏｎｅ－Ｔｉｃｋ",
    "ｓ．ｔｕｎ Ｓｌａｍ","ａ．ｕｔｏｍａｔｉｃａｌｌｙ ａｘｅ ａｎｄ ｍａｃｅ ｓｈｉｅｌｄｅｄ ｐｌａｙｅｒｓ",
    "ｔ．ｒｉｇ Ｈｅａｌｔｈ","ｐ．ｏｔ Ｃｏｕｎｔ","ｔ．ｈｒｏｗ Ｄｅｌａｙ","ａ．ｕｔｏ Ｒｅｆｉｌｌ","ｒ．ｅｆｉｌｌ Ｓｌｏｔ",
    "ｋ．ｅｙＰｅａｒｌ","ｘ．ｐ Ｍａｎａｇｅｒ","Ｏ．ｎ ＲＭＢ","Ｎ．ｏ Ｃｏｕｎｔ Ｇｌｉｔｃｈ","Ｆ．ａｓｔ Ｍｏｄｅ",
    "ａ．ｕｔｏＣｒｙｓｔａｌＬＶ２","ｒ．ｅｑｕｉｒｅ Ｃｏｂｗｅｂ","ａ．ｕｔｏ Ｗｅｂ","ｔ．ｒａｃｅｒｓ",
    "Ｌ．ｉｎｅ Ｗｉｄｔｈ","ｂ．ｏｘ Ａｌｐｈａ","ｓ．ｋｅｌｔｏｎ","Ｒ．ｅｎｄｅｒｓ ｅｎｔｉｔｉｅｓ ｔｈｒｏｕｇｈ ｗａｌｌｓ",
    "Ｏ．ｎｌｙ Ｗｈｉｌｅ Ｉｎ Ｗｅｂ","ａ．ｎｔｉＷｅｂ","ａ．ｕｔｏｍａｔｉｃａｌｌｙ ｂｒｅａｋｓ ｗｅｂｓ ａｒｏｕｎｄ ｙｏｕ",
    "ｔ．ｏｔｅｍ Ｓｌｏｔ","ｒ．ａｎｄｏｍ Ｄｅｌａｙ Ｍｉｎ","ｒ．ａｎｄｏｍ Ｄｅｌａｙ Ｍａｘ","ｒ．ａｎｄｏｍ Ｇｌｏｗｓｔｏｎｅ",
    "Ｗ．ｈｉｌｅ Ｕｓｅ","Ｏ．ｎ Ｌｅｆｔ Ｃｌｉｃｋ","Ａ．ｌｌ Ｉｔｅｍｓ","ｓ．ｗｏｒｄ Ｄｅｌａｙ Ｍｉｎ",
    "Ｓ．ｗｏｒｄ Ｄｅｌａｙ Ｍａｘ","ａ．ｘｅ Ｄｅｌａｙ Ｍａｘ","Ｃ．ｈｅｃｋ Ｓｈｉｅｌｄ",
    "Ｏ．ｎｌｙ Ｃｒｉｔ Ｓｗｏｒｄ","Ｏ．ｎｌｙ Ｃｒｉｔ Ａｘｅ","ｓ．ｗｉｔｃｈ Ｈｉｌｄ","Ｓ．ｈｉｌｄ Ｔｉｍｅ",
    "Ｓ．ｔｒａｙ ｂｙｐａｓｓ","ａ．ｌｌ Ｅｎｔｉｔｉｅｓ","ｕ．ｓｅ ｓｈｉｅｌｄ","ｓ．ｈｉｅｌｄ Ｔｉｍｅ",
    "Ｓ．ａｍｅ Ｐｌａｙｅｒ","Ｔ．ｒｉｇｇｅｒＢｏｔ","ｓ．ｔｏｐ ｏｎ ｋｉｌｌ","Ｇ．ｌｏｗｓｔｏｎｅ Ｄｅｌａｙ",
    "Ｇ．ｌｏｗｓｔｏｎｅ Ｃｈａｎｃｅ","Ｅ．ｘｐｌｏｄｅ Ｄｅｌａｙ","Ｅ．ｘｐｌｏｄｅ Ｃｈａｎｃｅ","Ｅ．ｘｐｌｏｄｅ Ｓｌｏｔ",
    "Ｏ．ｎｌｙ Ｏｗｎ","Ｏ．ｎｌｙ Ｃｈａｒｇｅ","Ａ．ｎｃｈｏｒ Ｍａｃｒｏ Ｖ２","Ｍ．ｉｎ Ｆａｌｌ Ｄｉｓｔａｎｃｅ",
    "Ａ．ｔｔａｃｋ Ｄｅｌａｙ","Ｄ．ｅｎｓｉｔｙ Ｔｈｒｅｓｈｏｌｄ","Ｔ．ａｒｇｅｔ Ｐｌａｙｅｒｓ","Ｔ．ａｒｇｅｔ Ｍｏｂｓ",
    "Ａ．ｕｔｏ Ｓｗｉｔｃｈ","Ａ．ｕｔｏ Ｍａｃｅ","Automatically attacks while falling with mace.",
    "Ｓ．ｈｏｗ Ｆｒｉｅｎｄｓ","Ｆ．ａｓｔ Ｐｌａｃｅ","Ｐ．ｌａｃｅ ｂｌｏｃｋｓ ｆａｓｔｅｒ",
    "Ｐ．ｒｅｖｅｎｔ Ａｎｃｈｏｒ","Ｐ．ｒｅｖｅｎｔｓ ｃｅｒｔａｉｎ ａｃｔｉｏｎｓ","Ｗ．ｉｎｄ Ｂｕｒｓｔ",
    "Ｏ．ｎｌｙ Ｓｗｏｒｄ","Ｏ．ｎｌｙ Ａｘｅ","Ｍ．ａｃｅ Ｓｗａｐ","Ｍ．ａｃｒｏ Ｋｅｙ","Ｂ．ｌａｔａｎｔ Ｍｏｄｅ",
    "Ｐ．ｌａｃｅ ｄｅｌａｙ","Ｂ．ｒｅａｋ ｄｅｌａｙ","Ｐ．ｌａｃｅ ｃｈａｎｃｅ","Ｂ．ｒｅａｋ ｃｈａｎｃｅ","Ｆ．ａｋｅ ｐｕｎｃｈ",
    "Ｐ．ａｒｔｉｃｌｅ Ｃｈａｎｃｅ","ｏ．ｎｅ ｎｉｎｅ ｅｉｇｈｔ Ｍａｃｒｏ","Ａ．ｕｔｏ Ｐｏｔ Ｒｅｆｉｌｌ",
    "Ｏ．ｎｌｙ Ｗｈｅｎ Ｈｕｒｔ","Ｔ．ｏｔｅｍ Ｏｆｆｈａｎｄ","Ａ．ｃｔｉｖａｔｅ ｋｅｙ","Ｓ．ｔｏｐ ｏｎ ｋｉｌｌ",
    "Ｄ．ａｍａｇｅ ｔｉｃｋ","Ａ．ｎｔｉ－Ｗｅａｋｎｅｓｓ","Ｒ．ｅｓｅｔ Ｄｅｌａｙ","Ｓ．ｈｏｗ Ｈｅａｌｔｈ",
    "Ｓ．ｈｏｗ Ｄｉｓｔａｎｃｅ","Ｎ．ａｍｅＴａｇｓ","Ｒ．ｅｎｄｅｒｓ ｃｕｓｔｏｍ ｎａｍｅｔａｇｓ ａｂｏｖｅ ｐｌａｙｅｒｓ"
)

 $verifiedMods = @()
 $unknownMods = @()
 $suspiciousMods = @()

try {
    $jarFiles = Get-ChildItem -Path $modsPath -Filter *.jar -Force -ErrorAction Stop
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}

if ($jarFiles.Count -eq 0) {
    Write-Host "No JAR files found." -ForegroundColor Yellow
    exit 0
}

Write-Host "Found $($jarFiles.Count) files. Verifying..." -ForegroundColor Gray

 $idx = 0
foreach ($jar in $jarFiles) {
    $idx++
    Write-Host "`r[$idx/$($jarFiles.Count)] Checking $($jar.Name)" -NoNewline
    
    $isHidden = ($jar.Attributes -band [System.IO.FileAttributes]::Hidden) -eq [System.IO.FileAttributes]::Hidden

    if ($jar.Name -match "coord[-_ ]?mod") {
        Write-Host ""
        Write-Host "Suspicious Dqrkis file found" -ForegroundColor Red
        Write-Host "    File: $($jar.Name)" -ForegroundColor Red
        $coordResult = Search-CoordmodClass -Path $jar.FullName
        if ($coordResult.EntryFound) {
            if ($coordResult.Matches.Count -gt 0) {
                Write-Host "    Inspected com/example/coordmod/compact/a/a/e/c/BlockC - matched $($coordResult.Matches.Count) indicator(s):" -ForegroundColor Red
                Write-Host "      $($coordResult.Matches -join ', ')" -ForegroundColor DarkRed
            } else {
                Write-Host "    Inspected com/example/coordmod/compact/a/a/e/c/BlockC - no listed indicators matched." -ForegroundColor DarkYellow
            }
        } else {
            Write-Host "    com/example/coordmod/compact/a/a/e/c/BlockC not found inside the JAR." -ForegroundColor DarkYellow
        }
        $src = Get-DownloadSource $jar.FullName
        $suspiciousMods += [PSCustomObject]@{ FileName = $jar.Name; FilePath = $jar.FullName; DownloadSource = $src; IsHidden = $isHidden; Matches = $coordResult.Matches }
        continue
    }
    
    $hash = Get-FileSHA1 -Path $jar.FullName
    
    if ($hash) {
        $modrinthData = Query-Modrinth -Hash $hash
        if ($modrinthData.Slug) {
            $verifiedMods += [PSCustomObject]@{ ModName = $modrinthData.Name; FileName = $jar.Name; IsHidden = $isHidden }
            Write-Host "`r" -NoNewline
            continue
        }
        $megabaseData = Query-Megabase -Hash $hash
        if ($megabaseData.name) {
            $verifiedMods += [PSCustomObject]@{ ModName = $megabaseData.Name; FileName = $jar.Name; IsHidden = $isHidden }
            Write-Host "`r" -NoNewline
            continue
        }
    }
    
    $src = Get-DownloadSource $jar.FullName
    $unknownMods += [PSCustomObject]@{ FileName = $jar.Name; FilePath = $jar.FullName; DownloadSource = $src; IsHidden = $isHidden }
    Write-Host "`r" -NoNewline
}

Write-Host "`rDeep Scanning unknown mods..." -ForegroundColor DarkGray

if ($unknownMods.Count -gt 0) {
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem

        # Read each unknown JAR's entry (file/class) names once.
        $modEntryNames = @{}
        foreach ($mod in $unknownMods) {
            $names = New-Object System.Collections.Generic.List[string]
            try {
                $archive = [System.IO.Compression.ZipFile]::OpenRead($mod.FilePath)
                foreach ($entry in $archive.Entries) { $null = $names.Add($entry.FullName) }
                $archive.Dispose()
            } catch {
            }
            $modEntryNames[$mod.FileName] = $names
        }

        # Match the suspicious patterns (in chunks) against every entry name and
        # remember every distinct string that matched, per mod.
        $modMatches = @{}
        $chunkSize = 50

        for ($c = 0; $c -lt $suspiciousPatterns.Count; $c += $chunkSize) {
            $end = [Math]::Min($c + $chunkSize - 1, $suspiciousPatterns.Count - 1)
            $chunk = $suspiciousPatterns[$c..$end]
            $escaped = $chunk | Where-Object { $_ } | ForEach-Object { [regex]::Escape($_) }
            $pattern = '(' + ($escaped -join '|') + ')'
            $regex = [regex]::new($pattern, [System.Text.RegularExpressions.RegexOptions]::Compiled -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

            foreach ($mod in $unknownMods) {
                foreach ($name in $modEntryNames[$mod.FileName]) {
                    foreach ($hit in $regex.Matches($name)) {
                        if (-not $modMatches.ContainsKey($mod.FileName)) {
                            $modMatches[$mod.FileName] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                        }
                        $null = $modMatches[$mod.FileName].Add($hit.Value)
                    }
                }
            }
        }

        foreach ($mod in $unknownMods) {
            if ($modMatches.ContainsKey($mod.FileName) -and $modMatches[$mod.FileName].Count -gt 0) {
                $suspiciousMods += [PSCustomObject]@{
                    FileName       = $mod.FileName
                    FilePath       = $mod.FilePath
                    DownloadSource = $mod.DownloadSource
                    IsHidden       = $mod.IsHidden
                    Matches        = @($modMatches[$mod.FileName] | Sort-Object)
                }
            }
        }
    } catch {
        Write-Host "Error during deep scan: $_" -ForegroundColor Red
    }
}

Write-Host "`n----------------------------------------"
Write-Host "SCAN COMPLETE" -ForegroundColor Cyan
Write-Host "----------------------------------------"

Write-Host "`nVerified Mods ($($verifiedMods.Count))" -ForegroundColor Green
if ($verifiedMods.Count -eq 0) { Write-Host "  None" }
foreach ($v in $verifiedMods) { 
    $h = if ($v.IsHidden) { " [HIDDEN]" } else { "" }
    Write-Host "  [OK] $($v.ModName) ($($v.FileName))$h" 
}

Write-Host "`nSuspicious Mods ($($suspiciousMods.Count))" -ForegroundColor Red
if ($suspiciousMods.Count -eq 0) { Write-Host "  None" }
foreach ($s in $suspiciousMods) {
    $src = if ($s.DownloadSource) { " [$($s.DownloadSource)]" } else { "" }
    $h = if ($s.IsHidden) { " [HIDDEN]" } else { "" }
    Write-Host "  [!] $($s.FileName)$src$h" -ForegroundColor Red
    $matched = @($s.Matches)
    if ($matched.Count -gt 0) {
        Write-Host "      Matched $($matched.Count) string(s): $($matched -join ', ')" -ForegroundColor DarkRed
    }
}

 $unknownCount = ($unknownMods | Where-Object { $suspiciousMods.FileName -notcontains $_.FileName }).Count
Write-Host "`nUnknown Mods ($unknownCount)" -ForegroundColor Yellow
if ($unknownCount -eq 0) { Write-Host "  None" }
foreach ($u in $unknownMods) {
    if ($suspiciousMods.FileName -notcontains $u.FileName) {
        $src = if ($u.DownloadSource) { " [$($u.DownloadSource)]" } else { "" }
        $h = if ($u.IsHidden) { " [HIDDEN]" } else { "" }
        Write-Host "  [?] $($u.FileName)$src$h" -ForegroundColor DarkYellow
    }
}
Write-Host ""
