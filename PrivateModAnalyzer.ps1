# ==============================================================================
# MINECRAFT FORENSIC MOD ANALYZER
# Features: Mod Listing, Log Keyword Scanning, Suspicious Config Detection
# ==============================================================================

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms

# --- GUI DEFINITION ---
[xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Minecraft Forensic Analyzer"
    Width="800"
    Height="600"
    WindowStartupLocation="CenterScreen"
    ResizeMode="CanMinimize"
    Background="#1e1e1e"
    Foreground="White"
    FontFamily="Consolas">

    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <TextBlock Grid.Row="0" Text="MINECRAFT FORENSIC TOOL" FontSize="18" FontWeight="Bold" Foreground="#00ffcc" Margin="0,0,0,10"/>

        <!-- Controls -->
        <StackPanel Grid.Row="1" Orientation="Horizontal" Margin="0,0,0,10">
            <Button x:Name="BrowseBtn" Content="Select .minecraft Folder" Width="200" Height="30" Background="#333" Foreground="White" Margin="0,0,10,0"/>
            <Button x:Name="AnalyzeBtn" Content="ANALYZE" Width="100" Height="30" Background="#00aa00" Foreground="White" FontWeight="Bold"/>
            <TextBlock x:Name="PathLabel" Text="No folder selected" VerticalAlignment="Center" Foreground="#aaa" Margin="10,0,0,0"/>
        </StackPanel>

        <!-- Output -->
        <Border Grid.Row="2" BorderBrush="#444" BorderThickness="1" Background="#111">
            <ScrollViewer VerticalScrollBarVisibility="Auto">
                <TextBlock x:Name="OutputBox" Text="Waiting for analysis..." Foreground="#00ffcc" Padding="10" TextWrapping="Wrap"/>
            </ScrollViewer>
        </Border>

        <!-- Footer -->
        <TextBlock Grid.Row="3" Text="Created for Mecz Launcher | v1.0" FontSize="10" Foreground="#555" HorizontalAlignment="Right" Margin="0,10,0,0"/>
    </Grid>
</Window>
"@

# --- LOGIC ---

 $reader = New-Object System.Xml.XmlNodeReader $xaml
 $window = [Windows.Markup.XamlReader]::Load($reader)

 $BrowseBtn = $window.FindName("BrowseBtn")
 $AnalyzeBtn = $window.FindName("AnalyzeBtn")
 $OutputBox = $window.FindName("OutputBox")
 $PathLabel = $window.FindName("PathLabel")

 $SelectedPath = ""

# Suspicious Keywords to look for in logs
 $SuspiciousKeywords = @(
    "bypass", "cheat", "hack", "killaura", "fly", "scaffold", "timer", 
    "autotool", "fullbright", "esp", "tracer", "noslow", "speed", "critical",
    "meteor", "liquid", "wurst", "impact", "rise", "future", "tenacity"
)

function Write-Output {
    param([string]$text, [string]$color = "#00ffcc")
    $OutputBox.Inlines.Add((New-Object Windows.Documents.Run "$text`r`n"))
    $OutputBox.Inlines[$OutputBox.Inlines.Count-1].Foreground = [Windows.Media.Brushes]::Parse($color)
}

function Select-Folder {
    $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($FolderBrowser.ShowDialog() -eq "OK") {
        $script:SelectedPath = $FolderBrowser.SelectedPath
        $PathLabel.Text = $script:SelectedPath
        Write-Output "Selected: $script:SelectedPath"
    }
}

function Start-Analysis {
    if ([string]::IsNullOrEmpty($SelectedPath)) {
        [System.Windows.MessageBox]::Show("Please select a folder first.")
        return
    }

    $OutputBox.Text = "" # Clear previous
    Write-Output "--- STARTING ANALYSIS ---" "#ffffff"
    Write-Output "Target: $SelectedPath" "#aaaaaa"
    Write-Output ""

    # 1. Check Mods Folder
    $ModsPath = Join-Path $SelectedPath "mods"
    if (Test-Path $ModsPath) {
        Write-Output "[1] SCANNING MODS FOLDER..." "#ffff00"
        $Mods = Get-ChildItem -Path $ModsPath -Filter "*.jar" -ErrorAction SilentlyContinue
        if ($Mods) {
            foreach ($Mod in $Mods) {
                $Name = $Mod.Name
                # Simple keyword check on filename
                $IsSuspicious = $false
                foreach ($kw in $SuspiciousKeywords) {
                    if ($Name -like "*$kw*") { $IsSuspicious = $true; break }
                }
                
                if ($IsSuspicious) {
                    Write-Output "  [!] SUSPICIOUS: $Name" "#ff4444"
                } else {
                    Write-Output "  [+] $Name" "#00cc00"
                }
            }
        } else {
            Write-Output "  No mods found or folder empty." "#aaaaaa"
        }
    } else {
        Write-Output "[1] MODS FOLDER NOT FOUND." "#ff4444"
    }
    Write-Output ""

    # 2. Scan Logs
    $LogsPath = Join-Path $SelectedPath "logs\latest.log"
    if (Test-Path $LogsPath) {
        Write-Output "[2] SCANNING LOGS FOR KEYWORDS..." "#ffff00"
        $LogContent = Get-Content $LogsPath -ErrorAction SilentlyContinue
        $Hits = 0
        
        foreach ($line in $LogContent) {
            foreach ($kw in $SuspiciousKeywords) {
                if ($line -match $kw) {
                    Write-Output "  [!] FOUND '$kw': $line" "#ff4444"
                    $Hits++
                }
            }
        }
        if ($Hits -eq 0) {
            Write-Output "  No suspicious keywords found in logs." "#00cc00"
        }
    } else {
        Write-Output "[2] LOGS NOT FOUND." "#aaaaaa"
    }
    Write-Output ""

    # 3. Check Options (Ghost client traces)
    $OptionsPath = Join-Path $SelectedPath "options.txt"
    if (Test-Path $OptionsPath) {
        Write-Output "[3] CHECKING OPTIONS.TXT..." "#ffff00"
        $Options = Get-Content $OptionsPath
        
        # Check for extremely high FOV (common in Xray/Cheats)
        $FovLine = $Options | Where-Object { $_ -like "fov:*" }
        if ($FovLine) {
            $FovVal = [float]($FovLine -split ":")[1]
            if ($FovVal -gt 130) {
                Write-Output "  [!] HIGH FOV DETECTED: $FovLine" "#ff0000"
            }
        }

        # Check for gamma (Fullbright)
        $GammaLine = $Options | Where-Object { $_ -like "gamma:*" }
        if ($GammaLine) {
            $GammaVal = [float]($GammaLine -split ":")[1]
            if ($GammaVal -gt 5.0) {
                Write-Output "  [!] HIGH GAMMA DETECTED: $GammaLine" "#ff0000"
            }
        }
    } else {
        Write-Output "[3] OPTIONS.TXT NOT FOUND." "#aaaaaa"
    }

    Write-Output ""
    Write-Output "--- ANALYSIS COMPLETE ---" "#ffffff"
}

# --- EVENTS ---
 $BrowseBtn.Add_Click({ Select-Folder })
 $AnalyzeBtn.Add_Click({ Start-Analysis })

 $window.ShowDialog() | Out-Null
