# ==============================================================================
# MECZ MOD ANALYZER (PRO EDITION)
# Features: Deep Jar Scan, Modrinth/Megabase Verification, Hash Checking
# ==============================================================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Clear-Host

 $Banner = @"

  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ██░███░██░███░██░░███░░███░███░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
  ██░░░░░██░░░░░██░░░██░░░██░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
  ████░░░░██░░░░░██░░░██░░░██░░█████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
  ██░███░░██░░░░░██░░░██░░░██░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
  ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀

"@

Write-Host $Banner -ForegroundColor Magenta
Write-Host "                          DEEP FORENSIC SCANNER" -ForegroundColor Cyan
Write-Host "                    Created by Mecz & MeowTonynoh" -ForegroundColor Gray
Write-Host ("━" * 76) -ForegroundColor DarkMagenta
Write-Host

# Get mods directory path from user
Write-Host "Enter path to the mods folder: " -NoNewline
Write-Host "(press Enter to use default)" -ForegroundColor DarkGray
 $modsPath = Read-Host "PATH"
Write-Host

if ([string]::IsNullOrWhiteSpace($modsPath)) {
    $modsPath = "$env:USERPROFILE\AppData\Roaming\.minecraft\mods"
    Write-Host "Continuing with " -NoNewline
    Write-Host $modsPath -ForegroundColor White
    Write-Host
}

if (-not (Test-Path $modsPath -PathType Container)) {
    Write-Host "❌ Invalid Path!" -ForegroundColor Red
    Write-Host "The directory does not exist or is not accessible." -ForegroundColor Yellow
    Write-Host
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

Write-Host "📁 Scanning directory: $modsPath" -ForegroundColor Green
Write-Host

# Check for running Minecraft instance
 $mcProcess = Get-Process javaw -ErrorAction SilentlyContinue
if (-not $mcProcess) {
    $mcProcess = Get-Process java -ErrorAction SilentlyContinue
}

if ($mcProcess) {
    try {
        $startTime = $mcProcess.StartTime
        $uptime = (Get-Date) - $startTime
        Write-Host "🕒 { Minecraft Uptime }" -ForegroundColor DarkCyan
        Write-Host "   $($mcProcess.Name) PID $($mcProcess.Id) started at $startTime" -ForegroundColor Gray
        Write-Host "   Running for: $($uptime.Hours)h $($uptime.Minutes)m $($uptime.Seconds)s" -ForegroundColor Gray
        Write-Host ""
    } catch {
        # Process info unavailable, continue silently
    }
}

function Get-FileSHA1 {
    param([string]$Path)
    return (Get-FileHash -Path $Path -Algorithm SHA1).Hash
}

function Get-DownloadSource {
    param([string]$Path)
    
    $zoneData = Get-Content -Raw -Stream Zone.Identifier $Path -ErrorAction SilentlyContinue
    if ($zoneData -match "HostUrl=(.+)") {
        $url = $matches[1].Trim()
        
        # Parse common download sources
        if ($url -match "mediafire\.com") { return "MediaFire" }
        elseif ($url -match "discord\.com|discordapp\.com|cdn\.discordapp\.com") { return "Discord" }
        elseif ($url -match "dropbox\.com") { return "Dropbox" }
        elseif ($url -match "drive\.google\.com") { return "Google Drive" }
        elseif ($url -match "mega\.nz|mega\.co\.nz") { return "MEGA" }
        elseif ($url -match "github\.com") { return "GitHub" }
        elseif ($url -match "modrinth\.com") { return "Modrinth" }
        elseif ($url -match "curseforge\.com") { return "CurseForge" }
        elseif ($url -match "anydesk\.com") { return "AnyDesk" }
        elseif ($url -match "doomsdayclient\.com") { return "DoomsdayClient" }
        elseif ($url -match "prestigeclient\.vip") { return "PrestigeClient" }
        elseif ($url -match "198macros\.com") { return "198Macros" }
        else {
            if ($url -match "https?://(?:www\.)?([^/]+)") {
                return $matches[1]
            }
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
    } catch {
        # Modrinth lookup failed
    }
    
    return @{ Name = ""; Slug = "" }
}

function Query-Megabase {
    param([string]$Hash)
    
    try {
        $result = Invoke-RestMethod -Uri "https://megabase.vercel.app/api/query?hash=$Hash" -Method Get -UseBasicParsing -ErrorAction Stop
        if (-not $result.error) {
            return $result.data
        }
    } catch {
        # Megabase unreachable
    }
    
    return $null
}

# Cheat/hack pattern database - compiled from known malicious mods
 $suspiciousPatterns = @(
    "AimAssist", "AnchorTweaks", "AutoAnchor", "AutoCrystal", "AutoDoubleHand",
    "AutoHitCrystal", "AutoPot", "AutoTotem", "AutoArmor", "InventoryTotem",
    "Hitboxes", "JumpReset", "LegitTotem", "PingSpoof", "SelfDestruct",
    "ShieldBreaker", "TriggerBot", "Velocity", "AxeSpam", "WebMacro",
    "FastPlace", "WalskyOptimizer", "WalksyOptimizer", "walsky.optimizer", 
    "WalksyCrystalOptimizerMod", "Donut", "Replace Mod", "Reach",
    "ShieldDisabler", "SilentAim", "Totem Hit", "Wtap", "FakeLag",
    "Friends", "NoDelay", "BlockESP", "Krypton", "krypton", "dev.krypton", "Virgin", "AntiMissClick",
    "LagReach", "PopSwitch", "SprintReset", "ChestSteal", "AntiBot",
    "ElytraSwap", "FastXP", "FastExp", "Refill", "NoJumpDelay", "AirAnchor",
    "jnativehook", "FakeInv", "HoverTotem", "AutoClicker", "AutoFirework",
    "Freecam", "PackSpoof", "Antiknockback", "scrim", "catlean", "Argon",
    "Discord", "AuthBypass", "Asteria", "Prestige", "AutoEat", "AutoMine",
    "MaceSwap", "DoubleAnchor", "AutoTPA", "BaseFinder", "Xenon", "gypsy",
    "Grim", "grim",
    "org.chainlibs.module.impl.modules.Crystal.Y",
    "org.chainlibs.module.impl.modules.Crystal.bF",
    "org.chainlibs.module.impl.modules.Crystal.bM",
    "org.chainlibs.module.impl.modules.Crystal.bY",
    "org.chainlibs.module.impl.modules.Crystal.bq",
    "org.chainlibs.module.impl.modules.Crystal.cv",
    "org.chainlibs.module.impl.modules.Crystal.o",
    "org.chainlibs.module.impl.modules.Blatant.I",
    "org.chainlibs.module.impl.modules.Blatant.bR",
    "org.chainlibs.module.impl.modules.Blatant.bx",
    "org.chainlibs.module.impl.modules.Blatant.cj",
    "org.chainlibs.module.impl.modules.Blatant.dk",
    "imgui", "imgui.gl3", "imgui.glfw",
    "BowAim", "Criticals", "Flight", "Fakenick", "FakeItem",
    "inject", "invsee", "ItemExploit", "Hellion", "hellion",
    "KeyboardMixin", "ClientPlayerInteractionManagerMixin",
    "LicenseCheckMixin", "ClientPlayerInteractionManagerAccessor",
    "ClientPlayerEntityMixim", "dev.gambleclient", "obfuscatedAuth",
    "phantom-refmap.json", "xyz.greaj",
    "じ.class", "ふ.class", "ぶ.class", "ぷ.class", "た.class",
    "ね.class", "そ.class", "な.class", "ど.class", "ぐ.class",
    "ず.class", "で.class", "つ.class", "べ.class", "せ.class",
    "と.class", "み.class", "び.class", "す.class", "の.class"
)

 $verifiedMods = @()
 $unknownMods = @()
 $suspiciousMods = @()

try {
    $jarFiles = Get-ChildItem -Path $modsPath -Filter *.jar -ErrorAction Stop
} catch {
    Write-Host "❌ Error accessing directory: $_" -ForegroundColor Red
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

if ($jarFiles.Count -eq 0) {
    Write-Host "⚠️  No JAR files found in: $modsPath" -ForegroundColor Yellow
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 0
}

Write-Host "🔍 Found $($jarFiles.Count) JAR file(s) to analyze" -ForegroundColor Green
Write-Host

 $spinnerFrames = @("⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷")
 $totalFiles = $jarFiles.Count
 $idx = 0

# Pass 1: Database verification
foreach ($jar in $jarFiles) {
    $idx++
    $spinner = $spinnerFrames[$idx % $spinnerFrames.Length]
    Write-Host "`r[$spinner] Scanning: $idx/$totalFiles - $($jar.Name)" -ForegroundColor Yellow -NoNewline
    
    $hash = Get-FileSHA1 -Path $jar.FullName
    
    if ($hash) {
        $modrinthData = Query-Modrinth -Hash $hash
        if ($modrinthData.Slug) {
            $verifiedMods += [PSCustomObject]@{ 
                ModName = $modrinthData.Name
                FileName = $jar.Name 
            }
            continue
        }
        
        $megabaseData = Query-Megabase -Hash $hash
        if ($megabaseData.name) {
            $verifiedMods += [PSCustomObject]@{ 
                ModName = $megabaseData.Name
                FileName = $jar.Name 
            }
            continue
        }
    }
    
    $src = Get-DownloadSource $jar.FullName
    $unknownMods += [PSCustomObject]@{ 
        FileName = $jar.Name
        FilePath = $jar.FullName
        DownloadSource = $src
    }
}

Write-Host "`r$(' ' * 100)`r" -NoNewline

# Pass 2: Deep pattern scan on unknown mods
if ($unknownMods.Count -gt 0) {
    Write-Host "🔬 Analyzing $($unknownMods.Count) unknown mod(s)..." -ForegroundColor Cyan
    
    $idx = 0
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        
        $pattern = '(' + ($suspiciousPatterns -join '|') + ')'
        $regex = [regex]::new($pattern, [System.Text.RegularExpressions.RegexOptions]::Compiled)
        
        foreach ($mod in $unknownMods) {
            $idx++
            $spinner = $spinnerFrames[$idx % $spinnerFrames.Length]
            Write-Host "`r[$spinner] Checking: $idx/$($unknownMods.Count) - $($mod.FileName)" -ForegroundColor Yellow -NoNewline
            
            $detected = [System.Collections.Generic.HashSet[string]]::new()
            
            try {
                $archive = [System.IO.Compression.ZipFile]::OpenRead($mod.FilePath)
                
                foreach ($entry in $archive.Entries) {
                    $matches = $regex.Matches($entry.FullName)
                    foreach ($m in $matches) {
                        [void]$detected.Add($m.Value)
                    }
                    
                    if ($entry.FullName -match '\.(class|json)$' -or $entry.FullName -match 'MANIFEST\.MF') {
                        try {
                            $stream = $entry.Open()
                            $reader = New-Object System.IO.StreamReader($stream)
                            $content = $reader.ReadToEnd()
                            $reader.Close()
                            $stream.Close()
                            
                            $contentMatches = $regex.Matches($content)
                            foreach ($m in $contentMatches) {
                                [void]$detected.Add($m.Value)
                            }
                        } catch {
                            # Entry read failed, skip
                        }
                    }
                }
                
                $archive.Dispose()
                
                if ($detected.Count -gt 0) {
                    $suspiciousMods += [PSCustomObject]@{ 
                        FileName = $mod.FileName
                        DetectedPatterns = $detected
                    }
                }
                
            } catch {
                # Archive corrupted or inaccessible
                continue
            }
        }
    } catch {
        Write-Host "`r⚠️  Error during deep scan: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "`r$(' ' * 100)`r" -NoNewline
}

# Results output
Write-Host "`n" + ("━" * 76) -ForegroundColor DarkMagenta

if ($verifiedMods.Count -gt 0) {
    Write-Host "✅ VERIFIED MODS ($($verifiedMods.Count))" -ForegroundColor Green
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    foreach ($mod in $verifiedMods) {
        Write-Host "  ✓ " -ForegroundColor Green -NoNewline
        Write-Host "$($mod.ModName)" -ForegroundColor White -NoNewline
        Write-Host " → " -ForegroundColor Gray -NoNewline
        Write-Host "$($mod.FileName)" -ForegroundColor DarkGray
    }
    Write-Host ""
}

if ($unknownMods.Count -gt 0) {
    Write-Host "❓ UNKNOWN MODS ($($unknownMods.Count))" -ForegroundColor Yellow
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    foreach ($mod in $unknownMods) {
        $name = $mod.FileName
        if ($name.Length -gt 50) {
            $name = $name.Substring(0, 47) + "..."
        }
        
        $nameLen = $name.Length
        $topLine = "  ╔═ ? " + $name + " " + ("═" * (65 - $nameLen)) + "╗"
        
        Write-Host $topLine -ForegroundColor Yellow
        
        $sourceText = if ($mod.DownloadSource) { "Source: $($mod.DownloadSource)" } else { "Source: ?" }
        $srcLen = $sourceText.Length
        $bottomLine = "  ╚═ " + $sourceText + " " + ("═" * (67 - $srcLen)) + "╝"
        Write-Host $bottomLine -ForegroundColor Yellow
        Write-Host ""
    }
}

if ($suspiciousMods.Count -gt 0) {
    Write-Host "🚨 SUSPICIOUS MODS ($($suspiciousMods.Count))" -ForegroundColor Red
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""
    foreach ($mod in $suspiciousMods) {
        Write-Host "  ╔═══ " -ForegroundColor Red -NoNewline
        Write-Host "FLAGGED" -ForegroundColor White -BackgroundColor Red -NoNewline
        Write-Host " ═══════════════════════════════════════════════════════════" -ForegroundColor Red
        Write-Host "  ║" -ForegroundColor Red
        Write-Host "  ║  File: " -ForegroundColor Red -NoNewline
        Write-Host "$($mod.FileName)" -ForegroundColor Yellow
        Write-Host "  ║" -ForegroundColor Red
        Write-Host "  ║  Detected Patterns:" -ForegroundColor Red
        
        $patterns = $mod.DetectedPatterns | Sort-Object
        foreach ($p in $patterns) {
            Write-Host "  ║    • " -ForegroundColor Red -NoNewline
            Write-Host "$p" -ForegroundColor White
        }
        
        Write-Host "  ║" -ForegroundColor Red
        Write-Host "  ╚═══════════════════════════════════════════════════════════════════════" -ForegroundColor Red
        Write-Host ""
    }
}

Write-Host "📊 SUMMARY" -ForegroundColor Magenta
Write-Host ("━" * 76) -ForegroundColor DarkMagenta
Write-Host "  Total files scanned: " -ForegroundColor Gray -NoNewline
Write-Host "$totalFiles" -ForegroundColor White
Write-Host "  Verified mods: " -ForegroundColor Gray -NoNewline
Write-Host "$($verifiedMods.Count)" -ForegroundColor Green
Write-Host "  Unknown mods: " -ForegroundColor Gray -NoNewline
Write-Host "$($unknownMods.Count)" -ForegroundColor Yellow
Write-Host "  Suspicious mods: " -ForegroundColor Gray -NoNewline
Write-Host "$($suspiciousMods.Count)" -ForegroundColor Red
Write-Host
Write-Host ("━" * 76) -ForegroundColor DarkMagenta
Write-Host ""
Write-Host "  ✨ Analysis complete! Thanks for using Mecz Mod Analyzer 🐈" -ForegroundColor Cyan
Write-Host ""
Write-Host "  👤 Mecz Team" -ForegroundColor Magenta
Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor DarkGray
 $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
