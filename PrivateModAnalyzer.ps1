# ==============================================================================
# MINECRAFT FORENSIC MOD ANALYZER (VISUAL FIX)
# ==============================================================================

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms

# --- GUI DEFINITION ---
[xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Minecraft Forensic Analyzer"
    Width="900"
    Height="600"
    WindowStartupLocation="CenterScreen"
    ResizeMode="CanMinimize"
    Background="#1e1e1e"
    Foreground="White"
    FontFamily="Segoe UI">

    <Grid Margin="15">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <TextBlock Grid.Row="0" Text="MINECRAFT FORENSIC TOOL" FontSize="20" FontWeight="Bold" Foreground="#00ffcc" Margin="0,0,0,15"/>

        <!-- CONTROLS (New Layout) -->
        <Grid Grid.Row="1" Margin="0,0,0,15">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>

            <!-- Buttons -->
            <Button x:Name="BrowseBtn" Grid.Column="0" Content="Browse Folder" Width="120" Height="35" Background="#444" Foreground="White" Margin="0,0,10,0" FontSize="12"/>
            <Button x:Name="PasteBtn"   Grid.Column="1" Content="PASTE PATH" Width="100" Height="35" Background="#007acc" Foreground="White" Margin="0,0,10,0" FontWeight="Bold" FontSize="12"/>
            <Button x:Name="AnalyzeBtn" Grid.Column="2" Content="ANALYZE"     Width="100" Height="35" Background="#28a745" Foreground="White" FontWeight="Bold" FontSize="12"/>

            <!-- TEXT BOX (Made obvious) -->
            <TextBox x:Name="PathBox" 
                     Grid.Column="3" 
                     Text="CLICK HERE AND PASTE PATH (Ctrl+V) OR CLICK PASTE BUTTON" 
                     Background="#333" 
                     Foreground="White" 
                     BorderBrush="#00ccff" 
                     BorderThickness="2"
                     FontSize="12"
                     Padding="5"
                     VerticalContentAlignment="Center"
                     Margin="10,0,0,0"/>
        </Grid>

        <!-- Output -->
        <Border Grid.Row="2" BorderBrush="#444" BorderThickness="1" Background="#111">
            <ScrollViewer VerticalScrollBarVisibility="Auto">
                <TextBlock x:Name="OutputBox" Text="Waiting for analysis..." Foreground="#00ffcc" Padding="10" TextWrapping="Wrap" FontFamily="Consolas" FontSize="11"/>
            </ScrollViewer>
        </Border>

        <!-- Footer -->
        <TextBlock Grid.Row="3" Text="Mecz Forensic Tool v1.2 | Explicit Paste Support" FontSize="10" Foreground="#666" HorizontalAlignment="Right" Margin="0,10,0,0"/>
    </Grid>
</Window>
"@

# --- LOGIC ---

 $reader = New-Object System.Xml.XmlNodeReader $xaml
 $window = [Windows.Markup.XamlReader]::Load($reader)

 $BrowseBtn = $window.FindName("BrowseBtn")
 $PasteBtn  = $window.FindName("PasteBtn")
 $AnalyzeBtn = $window.FindName("AnalyzeBtn")
 $OutputBox = $window.FindName("OutputBox")
 $PathBox   = $window.FindName("PathBox")

# Suspicious Keywords
 $SuspiciousKeywords = @(
    "bypass", "cheat", "hack", "killaura", "fly", "scaffold", "timer", 
    "autotool", "fullbright", "esp", "tracer", "noslow", "speed", "critical",
    "meteor", "liquid", "wurst", "impact", "rise", "future", "tenacity", "reach", "autoclicker"
)

function Write-Output {
    param([string]$text, [string]$color = "#00ffcc")
    $OutputBox.Inlines.Add((New-Object Windows.Documents.Run "$text`r`n"))
    $OutputBox.Inlines[$OutputBox.Inlines.Count-1].Foreground = [Windows.Media.Brushes]::Parse($color)
}

function Select-Folder {
    $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($FolderBrowser.ShowDialog() -eq "OK") {
        $PathBox.Text = $FolderBrowser.SelectedPath
    }
}

function Paste-Clipboard {
    try {
        $ClipboardText = [System.Windows.Forms.Clipboard]::GetText()
        if (-not [string]::IsNullOrWhiteSpace($ClipboardText)) {
            $PathBox.Text = $ClipboardText
        } else {
            [System.Windows.MessageBox]::Show("Clipboard is empty.")
        }
    } catch {
        [System.Windows.MessageBox]::Show("Could not read clipboard.")
    }
}

function Start-Analysis {
    $TargetPath = $PathBox.Text

    if ([string]::IsNullOrWhiteSpace($TargetPath)) {
        [System.Windows.MessageBox]::Show("Please enter, paste, or select a path first.")
        return
    }

    if (!(Test-Path $TargetPath)) {
        [System.Windows.MessageBox]::Show("The path does not exist.`n`nPath: $TargetPath")
        return
    }

    $OutputBox.Text = "" 
    Write-Output "--- STARTING ANALYSIS ---" "#ffffff"
    Write-Output "Target: $TargetPath" "#aaaaaa"
    Write-Output ""

    # 1. Check Mods Folder
    $ModsPath = Join-Path $TargetPath "mods"
    if (Test-Path $ModsPath) {
        Write-Output "[1] SCANNING MODS FOLDER..." "#ffff00"
        $Mods = Get-ChildItem -Path $ModsPath -Filter "*.jar" -ErrorAction SilentlyContinue
        if ($Mods) {
            foreach ($Mod in $Mods) {
                $Name = $Mod.Name
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
    $LogsPath = Join-Path $TargetPath "logs\latest.log"
    if (Test-Path $LogsPath) {
        Write-Output "[2] SCANNING LOGS FOR KEYWORDS..." "#ffff00"
        $LogContent = Get-Content $LogsPath -ErrorAction SilentlyContinue
        $Hits = 0
        
        foreach ($line in $LogContent) {
            foreach ($kw in $SuspiciousKeywords) {
                if ($line -match $kw) {
                    $ShortLine = if ($line.Length -gt 100) { $line.Substring(0, 100) + "..." } else { $line }
                    Write-Output "  [!] FOUND '$kw': $ShortLine" "#ff4444"
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

    # 3. Check Options
    $OptionsPath = Join-Path $TargetPath "options.txt"
    if (Test-Path $OptionsPath) {
        Write-Output "[3] CHECKING OPTIONS.TXT..." "#ffff00"
        $Options = Get-Content $OptionsPath
        
        $FovLine = $Options | Where-Object { $_ -like "fov:*" }
        if ($FovLine) {
            if ($FovLine -match "fov:(.*)") {
                $FovVal = [float]$matches[1]
                if ($FovVal -gt 130) {
                    Write-Output "  [!] HIGH FOV DETECTED: $FovLine" "#ff0000"
                }
            }
        }

        $GammaLine = $Options | Where-Object { $_ -like "gamma:*" }
        if ($GammaLine) {
            if ($GammaLine -match "gamma:(.*)") {
                $GammaVal = [float]$matches[1]
                if ($GammaVal -gt 5.0) {
                    Write-Output "  [!] HIGH GAMMA DETECTED: $GammaLine" "#ff0000"
                }
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
 $PasteBtn.Add_Click({ Paste-Clipboard })
 $AnalyzeBtn.Add_Click({ Start-Analysis })

 $window.ShowDialog() | Out-Null
