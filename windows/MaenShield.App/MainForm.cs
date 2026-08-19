using MaenShield.Core;
using MaenShield.Infrastructure;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace MaenShield.App
{
    public sealed class MainForm : Form
    {
        private readonly CloudUpdateService updater;
        private readonly string storageRoot;
        private ThreatDatabaseSnapshot database;
        private CancellationTokenSource cancellation;
        private bool arabic;
        private bool busy;
        private string appVersionName;

        private Panel pageHost;
        private Label pageTitle;
        private Label pageSubtitle;
        private Label headerDatabase;
        private Label headerStatus;
        private ShieldMark headerMark;
        private Button overviewNav;
        private Button scanNav;
        private Button quarantineNav;
        private Button updatesNav;
        private Button settingsNav;
        private Button headerUpdateButton;

        private TextBox targetBox;
        private Button scanButton;
        private Button updateButton;
        private Button browseButton;
        private ComboBox languageBox;
        private Label statusLabel;
        private ProgressBar progressBar;
        private ListView resultsView;
        private ListView quarantineView;
        private Label protectionValue;
        private Label protectionDetail;
        private Label lastScanValue;
        private Label databaseValue;
        private Label filesValue;
        private Label threatsValue;
        private Label reviewsValue;
        private Label overviewMessage;
        private Label quarantineCount;
        private Label updateDetail;
        private Button quickScanButton;
        private Button quickUpdateButton;
        private Panel overviewPage;
        private Panel scanPage;
        private Panel quarantinePage;
        private Panel updatesPage;
        private Panel settingsPage;

        private readonly Color sidebarColor = Color.FromArgb(10, 29, 50);
        private readonly Color accentColor = Color.FromArgb(23, 119, 210);
        private readonly Color pageColor = Color.FromArgb(244, 247, 251);
        private readonly Color textColor = Color.FromArgb(24, 42, 60);
        private readonly Color mutedColor = Color.FromArgb(103, 122, 143);
        private readonly Color safeColor = Color.FromArgb(25, 137, 91);
        private readonly Color reviewColor = Color.FromArgb(193, 119, 17);
        private readonly Color dangerColor = Color.FromArgb(193, 58, 72);

        public MainForm(string storageRoot, int appVersionCode, string appVersionName)
        {
            this.storageRoot = storageRoot;
            this.appVersionName = appVersionName;
            updater = new CloudUpdateService(storageRoot, appVersionCode, CloudUpdateService.DefaultBaseUrl);
            arabic = System.Globalization.CultureInfo.CurrentUICulture.Name.StartsWith("ar", StringComparison.OrdinalIgnoreCase);
            InitializeUi();
            LoadActiveDatabase();
        }

        private void InitializeUi()
        {
            Text = "Maen Shield";
            MinimumSize = new Size(1040, 680);
            Size = new Size(1180, 760);
            StartPosition = FormStartPosition.CenterScreen;
            AutoScaleMode = AutoScaleMode.Dpi;
            Font = new Font("Segoe UI", 9F);
            BackColor = pageColor;
            DoubleBuffered = true;

            var shell = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = pageColor };
            shell.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 238F));
            shell.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            Controls.Add(shell);

            var sidebar = BuildSidebar();
            shell.Controls.Add(sidebar, 0, 0);

            var main = new Panel { Dock = DockStyle.Fill, BackColor = pageColor, Padding = new Padding(28, 24, 28, 24) };
            shell.Controls.Add(main, 1, 0);

            var header = new Panel { Dock = DockStyle.Top, Height = 76, BackColor = pageColor };
            main.Controls.Add(header);
            headerMark = new ShieldMark { Location = new Point(0, 9), Size = new Size(50, 54), Accent = accentColor };
            header.Controls.Add(headerMark);
            pageTitle = new Label { AutoSize = true, Location = new Point(65, 8), Font = new Font("Segoe UI", 22F, FontStyle.Bold), ForeColor = textColor };
            pageSubtitle = new Label { AutoSize = true, Location = new Point(67, 46), Font = new Font("Segoe UI", 9.5F), ForeColor = mutedColor };
            header.Controls.Add(pageTitle);
            header.Controls.Add(pageSubtitle);
            headerStatus = new Label { AutoSize = true, Anchor = AnchorStyles.Top | AnchorStyles.Right, Location = new Point(650, 10), Font = new Font("Segoe UI", 9F, FontStyle.Bold), ForeColor = safeColor, TextAlign = ContentAlignment.MiddleRight };
            headerDatabase = new Label { AutoSize = true, Anchor = AnchorStyles.Top | AnchorStyles.Right, Location = new Point(650, 35), Font = new Font("Segoe UI", 8.5F), ForeColor = mutedColor, TextAlign = ContentAlignment.MiddleRight };
            headerUpdateButton = MakeButton("Update", 104, 34, accentColor, Color.White);
            headerUpdateButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            headerUpdateButton.Location = new Point(760, 18);
            headerUpdateButton.Click += async (s, e) => await UpdateAsync();
            header.Controls.Add(headerStatus);
            header.Controls.Add(headerDatabase);
            header.Controls.Add(headerUpdateButton);

            pageHost = new Panel { Dock = DockStyle.Fill, BackColor = pageColor, AutoScroll = true };
            main.Controls.Add(pageHost);

            BuildPages();
            ApplyLanguage(arabic);
            ShowPage("overview");
        }

        private Panel BuildSidebar()
        {
            var sidebar = new Panel { Dock = DockStyle.Fill, BackColor = sidebarColor, Padding = new Padding(18, 22, 18, 18) };
            var brand = new Panel { Dock = DockStyle.Top, Height = 75, BackColor = sidebarColor };
            var mark = new ShieldMark { Location = new Point(0, 4), Size = new Size(46, 52), Accent = Color.FromArgb(60, 167, 255) };
            brand.Controls.Add(mark);
            var brandTitle = new Label { AutoSize = true, Location = new Point(58, 8), ForeColor = Color.White, Font = new Font("Segoe UI", 15F, FontStyle.Bold), Text = "Maen Shield" };
            var brandSub = new Label { AutoSize = true, Location = new Point(60, 36), ForeColor = Color.FromArgb(155, 180, 204), Font = new Font("Segoe UI", 8.5F), Text = "Free protection" };
            brand.Controls.Add(brandTitle);
            brand.Controls.Add(brandSub);
            sidebar.Controls.Add(brand);

            var nav = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 280, FlowDirection = FlowDirection.TopDown, WrapContents = false, BackColor = sidebarColor, Padding = new Padding(0, 10, 0, 0) };
            overviewNav = MakeNavButton("Overview", "◉");
            scanNav = MakeNavButton("Scan", "⌕");
            quarantineNav = MakeNavButton("Quarantine", "▣");
            updatesNav = MakeNavButton("Updates", "↻");
            settingsNav = MakeNavButton("Settings", "⚙");
            overviewNav.Click += (s, e) => ShowPage("overview");
            scanNav.Click += (s, e) => ShowPage("scan");
            quarantineNav.Click += (s, e) => { RefreshQuarantine(); ShowPage("quarantine"); };
            updatesNav.Click += (s, e) => ShowPage("updates");
            settingsNav.Click += (s, e) => ShowPage("settings");
            nav.Controls.Add(overviewNav);
            nav.Controls.Add(scanNav);
            nav.Controls.Add(quarantineNav);
            nav.Controls.Add(updatesNav);
            nav.Controls.Add(settingsNav);
            sidebar.Controls.Add(nav);

            var footer = new Panel { Dock = DockStyle.Bottom, Height = 92, BackColor = sidebarColor };
            var footerLine = new Panel { Dock = DockStyle.Top, Height = 1, BackColor = Color.FromArgb(42, 67, 91) };
            footer.Controls.Add(footerLine);
            var footerText = new Label { Dock = DockStyle.Fill, Padding = new Padding(0, 17, 0, 0), ForeColor = Color.FromArgb(141, 167, 191), Font = new Font("Segoe UI", 8.5F), Text = "Signed intelligence\nDaily protection updates", TextAlign = ContentAlignment.TopLeft };
            footer.Controls.Add(footerText);
            sidebar.Controls.Add(footer);
            return sidebar;
        }

        private void BuildPages()
        {
            overviewPage = BuildOverviewPage();
            scanPage = BuildScanPage();
            updatesPage = BuildUpdatesPage();
            quarantinePage = BuildQuarantinePage();
            settingsPage = BuildSettingsPage();
        }

        private Panel BuildOverviewPage()
        {
            var page = NewPage();
            var statusCard = new SurfacePanel { Dock = DockStyle.Top, Height = 178, Padding = new Padding(24), BackColor = Color.White };
            var mark = new ShieldMark { Location = new Point(24, 47), Size = new Size(78, 86), Accent = safeColor };
            statusCard.Controls.Add(mark);
            protectionValue = new Label { AutoSize = true, Location = new Point(130, 31), Font = new Font("Segoe UI", 25F, FontStyle.Bold), ForeColor = safeColor };
            protectionDetail = new Label { AutoSize = true, Location = new Point(132, 74), MaximumSize = new Size(480, 42), Font = new Font("Segoe UI", 10F), ForeColor = mutedColor };
            overviewMessage = new Label { AutoSize = true, Location = new Point(132, 119), Font = new Font("Segoe UI", 9F, FontStyle.Bold), ForeColor = textColor };
            statusCard.Controls.Add(protectionValue);
            statusCard.Controls.Add(protectionDetail);
            statusCard.Controls.Add(overviewMessage);
            quickScanButton = MakeButton("Scan now", 128, 38, accentColor, Color.White);
            quickScanButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            quickScanButton.Location = new Point(700, 66);
            quickScanButton.Click += (s, e) => ShowPage("scan");
            statusCard.Controls.Add(quickScanButton);
            page.Controls.Add(statusCard);

            var actions = new TableLayoutPanel { Dock = DockStyle.Top, Height = 126, ColumnCount = 3, RowCount = 1, Padding = new Padding(0, 18, 0, 0) };
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33F));
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33F));
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.34F));
            quickUpdateButton = AddActionCard(actions, 0, "Intelligence", "Keep your protection current", "Update", accentColor, async (s, e) => await UpdateAsync());
            AddActionCard(actions, 1, "Quarantine", "Review isolated files safely", "Open", Color.FromArgb(87, 105, 126), (s, e) => { RefreshQuarantine(); ShowPage("quarantine"); });
            AddActionCard(actions, 2, "Privacy", "Local-first protection controls", "Settings", Color.FromArgb(87, 105, 126), (s, e) => ShowPage("settings"));
            page.Controls.Add(actions);

            var stats = new TableLayoutPanel { Dock = DockStyle.Top, Height = 114, ColumnCount = 5, RowCount = 1, Padding = new Padding(0, 16, 0, 0) };
            for (var i = 0; i < 5; i++) stats.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 20F));
            AddStatCard(stats, 0, "Last scan", "Not run", out lastScanValue);
            AddStatCard(stats, 1, "Intelligence", "Not installed", out databaseValue);
            AddStatCard(stats, 2, "Files checked", "0", out filesValue);
            AddStatCard(stats, 3, "Threats", "0", out threatsValue);
            AddStatCard(stats, 4, "Review", "0", out reviewsValue);
            page.Controls.Add(stats);

            var recent = new SurfacePanel { Dock = DockStyle.Fill, Padding = new Padding(20), BackColor = Color.White };
            var recentTitle = new Label { Dock = DockStyle.Top, Height = 28, Font = new Font("Segoe UI", 12F, FontStyle.Bold), ForeColor = textColor, Text = "Recent activity" };
            recent.Controls.Add(recentTitle);
            var recentText = new Label { Dock = DockStyle.Fill, ForeColor = mutedColor, Text = "Your latest scan findings and protection events will appear here.", Padding = new Padding(0, 10, 0, 0) };
            recent.Controls.Add(recentText);
            page.Controls.Add(recent);
            return page;
        }

        private Button AddActionCard(TableLayoutPanel table, int column, string title, string subtitle, string action, Color color, EventHandler handler)
        {
            var card = new SurfacePanel { Dock = DockStyle.Fill, Margin = new Padding(column == 0 ? 0 : 7, 0, column == 2 ? 0 : 7, 0), Padding = new Padding(16), BackColor = Color.White };
            var titleLabel = new Label { AutoSize = true, Location = new Point(16, 13), Font = new Font("Segoe UI", 10F, FontStyle.Bold), ForeColor = textColor, Text = title };
            var subLabel = new Label { AutoSize = true, Location = new Point(16, 40), Font = new Font("Segoe UI", 8F), ForeColor = mutedColor, Text = subtitle };
            var button = MakeButton(action, 84, 28, color, Color.White);
            button.Location = new Point(16, 72);
            button.Click += handler;
            card.Controls.Add(titleLabel);
            card.Controls.Add(subLabel);
            card.Controls.Add(button);
            table.Controls.Add(card, column, 0);
            return button;
        }

        private Panel AddStatCard(TableLayoutPanel table, int column, string title, string value, out Label valueLabel)
        {
            var card = new SurfacePanel { Dock = DockStyle.Fill, Margin = new Padding(column == 0 ? 0 : 7, 0, column == 4 ? 0 : 7, 0), Padding = new Padding(16), BackColor = Color.White };
            var titleLabel = new Label { AutoSize = true, Location = new Point(16, 13), Font = new Font("Segoe UI", 8.5F), ForeColor = mutedColor, Text = title };
            valueLabel = new Label { AutoSize = true, Location = new Point(16, 38), Font = new Font("Segoe UI", 15F, FontStyle.Bold), ForeColor = textColor, Text = value };
            card.Controls.Add(titleLabel);
            card.Controls.Add(valueLabel);
            table.Controls.Add(card, column, 0);
            return card;
        }

        private Panel BuildScanPage()
        {
            var page = NewPage();
            var intro = new Label { Dock = DockStyle.Top, Height = 44, Font = new Font("Segoe UI", 10F), ForeColor = mutedColor, Text = "Scan a folder or file with the local engine and signed intelligence." };
            page.Controls.Add(intro);
            var scanCard = new SurfacePanel { Dock = DockStyle.Top, Height = 152, Padding = new Padding(20), BackColor = Color.White };
            var scanTitle = new Label { AutoSize = true, Location = new Point(20, 16), Font = new Font("Segoe UI", 13F, FontStyle.Bold), ForeColor = textColor, Text = "Smart scan" };
            var scanHint = new Label { AutoSize = true, Location = new Point(20, 45), Font = new Font("Segoe UI", 8.5F), ForeColor = mutedColor, Text = "Legal archives are inspected before any verdict is issued." };
            targetBox = new TextBox { Location = new Point(20, 79), Width = 520, Height = 30, Font = new Font("Segoe UI", 10F), Text = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) };
            browseButton = MakeButton("Browse", 96, 32, Color.FromArgb(87, 105, 126), Color.White);
            browseButton.Location = new Point(552, 77);
            scanButton = MakeButton("Scan now", 120, 32, accentColor, Color.White);
            scanButton.Location = new Point(657, 77);
            progressBar = new ProgressBar { Location = new Point(20, 119), Width = 757, Height = 7, Minimum = 0, Maximum = 100, Style = ProgressBarStyle.Continuous };
            scanCard.Controls.Add(scanTitle);
            scanCard.Controls.Add(scanHint);
            scanCard.Controls.Add(targetBox);
            scanCard.Controls.Add(browseButton);
            scanCard.Controls.Add(scanButton);
            scanCard.Controls.Add(progressBar);
            page.Controls.Add(scanCard);

            var resultsCard = new SurfacePanel { Dock = DockStyle.Fill, Padding = new Padding(18), BackColor = Color.White };
            statusLabel = new Label { Dock = DockStyle.Top, Height = 30, Font = new Font("Segoe UI", 9F), ForeColor = mutedColor, Text = "Ready to scan." };
            resultsCard.Controls.Add(statusLabel);
            resultsView = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = false, HideSelection = false, MultiSelect = false, BorderStyle = BorderStyle.None, HeaderStyle = ColumnHeaderStyle.Nonclickable, Font = new Font("Segoe UI", 9F) };
            resultsView.Columns.Add("Severity", 105);
            resultsView.Columns.Add("Path", 350);
            resultsView.Columns.Add("Reason", 380);
            resultsView.Columns.Add("Confidence", 100);
            resultsCard.Controls.Add(resultsView);
            page.Controls.Add(resultsCard);
            browseButton.Click += BrowseButton_Click;
            scanButton.Click += async (s, e) => await ScanAsync();
            return page;
        }

        private Panel BuildUpdatesPage()
        {
            var page = NewPage();
            var intro = new Label { Dock = DockStyle.Top, Height = 44, Font = new Font("Segoe UI", 10F), ForeColor = mutedColor, Text = "Signed threat intelligence keeps both Android and Windows protection current." };
            page.Controls.Add(intro);
            var card = new SurfacePanel { Dock = DockStyle.Top, Height = 190, Padding = new Padding(24), BackColor = Color.White };
            var mark = new ShieldMark { Location = new Point(24, 50), Size = new Size(70, 78), Accent = accentColor };
            card.Controls.Add(mark);
            var title = new Label { AutoSize = true, Location = new Point(120, 30), Font = new Font("Segoe UI", 17F, FontStyle.Bold), ForeColor = textColor, Text = "Intelligence database" };
            updateDetail = new Label { AutoSize = true, Location = new Point(122, 72), MaximumSize = new Size(580, 48), Font = new Font("Segoe UI", 9.5F), ForeColor = mutedColor };
            updateButton = MakeButton("Check for updates", 150, 38, accentColor, Color.White);
            updateButton.Location = new Point(122, 126);
            updateButton.Click += async (s, e) => await UpdateAsync();
            card.Controls.Add(title);
            card.Controls.Add(updateDetail);
            card.Controls.Add(updateButton);
            page.Controls.Add(card);
            var note = new SurfacePanel { Dock = DockStyle.Top, Height = 100, Padding = new Padding(20), BackColor = Color.White };
            var noteTitle = new Label { AutoSize = true, Location = new Point(20, 16), Font = new Font("Segoe UI", 10F, FontStyle.Bold), ForeColor = textColor, Text = "Automatic protection updates" };
            var noteText = new Label { AutoSize = true, Location = new Point(20, 45), Font = new Font("Segoe UI", 8.5F), ForeColor = mutedColor, Text = "Windows checks the free signed intelligence channel every 24 hours." };
            note.Controls.Add(noteTitle);
            note.Controls.Add(noteText);
            page.Controls.Add(note);
            return page;
        }

        private Panel BuildQuarantinePage()
        {
            var page = NewPage();
            var intro = new Label { Dock = DockStyle.Top, Height = 44, Font = new Font("Segoe UI", 10F), ForeColor = mutedColor, Text = "Files moved here are kept isolated and can be restored after review." };
            page.Controls.Add(intro);
            var toolbar = new SurfacePanel { Dock = DockStyle.Top, Height = 70, Padding = new Padding(18), BackColor = Color.White };
            quarantineCount = new Label { AutoSize = true, Location = new Point(18, 22), Font = new Font("Segoe UI", 11F, FontStyle.Bold), ForeColor = textColor, Text = "0 isolated items" };
            var refresh = MakeButton("Refresh", 92, 30, Color.FromArgb(87, 105, 126), Color.White);
            refresh.Location = new Point(650, 18);
            refresh.Click += (s, e) => RefreshQuarantine();
            var restore = MakeButton("Restore selected", 125, 30, accentColor, Color.White);
            restore.Location = new Point(748, 18);
            restore.Click += (s, e) => RestoreSelectedQuarantine();
            toolbar.Controls.Add(quarantineCount);
            toolbar.Controls.Add(refresh);
            toolbar.Controls.Add(restore);
            page.Controls.Add(toolbar);
            var listCard = new SurfacePanel { Dock = DockStyle.Fill, Padding = new Padding(18), BackColor = Color.White };
            quarantineView = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = false, BorderStyle = BorderStyle.None, HideSelection = false, HeaderStyle = ColumnHeaderStyle.Nonclickable };
            quarantineView.Columns.Add("Date", 145);
            quarantineView.Columns.Add("Original path", 520);
            quarantineView.Columns.Add("SHA-256", 300);
            listCard.Controls.Add(quarantineView);
            page.Controls.Add(listCard);
            return page;
        }

        private Panel BuildSettingsPage()
        {
            var page = NewPage();
            var intro = new Label { Dock = DockStyle.Top, Height = 44, Font = new Font("Segoe UI", 10F), ForeColor = mutedColor, Text = "Keep Maen Shield lightweight, private, and easy to understand." };
            page.Controls.Add(intro);
            var languageCard = new SurfacePanel { Dock = DockStyle.Top, Height = 116, Padding = new Padding(20), BackColor = Color.White };
            var languageTitle = new Label { AutoSize = true, Location = new Point(20, 18), Font = new Font("Segoe UI", 11F, FontStyle.Bold), ForeColor = textColor, Text = "Language" };
            var languageHint = new Label { AutoSize = true, Location = new Point(20, 49), Font = new Font("Segoe UI", 8.5F), ForeColor = mutedColor, Text = "Choose the interface language." };
            languageBox = new ComboBox { Location = new Point(620, 30), Width = 170, DropDownStyle = ComboBoxStyle.DropDownList, Font = new Font("Segoe UI", 9F) };
            languageBox.Items.AddRange(new object[] { "English", "العربية" });
            languageBox.SelectedIndex = arabic ? 1 : 0;
            languageBox.SelectedIndexChanged += (s, e) => ApplyLanguage(languageBox.SelectedIndex == 1);
            languageCard.Controls.Add(languageTitle);
            languageCard.Controls.Add(languageHint);
            languageCard.Controls.Add(languageBox);
            page.Controls.Add(languageCard);
            var privacyCard = new SurfacePanel { Dock = DockStyle.Top, Height = 130, Padding = new Padding(20), BackColor = Color.White };
            var privacyTitle = new Label { AutoSize = true, Location = new Point(20, 18), Font = new Font("Segoe UI", 11F, FontStyle.Bold), ForeColor = textColor, Text = "Local-first protection" };
            var privacyText = new Label { AutoSize = true, Location = new Point(20, 50), MaximumSize = new Size(800, 60), Font = new Font("Segoe UI", 8.5F), ForeColor = mutedColor, Text = "Files are scanned locally. Only signed threat intelligence metadata is downloaded from the free GitHub channel; personal files are not uploaded by this application." };
            privacyCard.Controls.Add(privacyTitle);
            privacyCard.Controls.Add(privacyText);
            page.Controls.Add(privacyCard);
            var aboutCard = new SurfacePanel { Dock = DockStyle.Top, Height = 94, Padding = new Padding(20), BackColor = Color.White };
            var about = new Label { AutoSize = true, Location = new Point(20, 18), Font = new Font("Segoe UI", 9F, FontStyle.Bold), ForeColor = textColor, Text = "Maen Shield for Windows" };
            var aboutVersion = new Label { AutoSize = true, Location = new Point(20, 48), Font = new Font("Segoe UI", 8.5F), ForeColor = mutedColor, Text = "Free protection • " + appVersionName + " • Built with Manus AI contribution" };
            aboutCard.Controls.Add(about);
            aboutCard.Controls.Add(aboutVersion);
            page.Controls.Add(aboutCard);
            return page;
        }

        private Panel NewPage()
        {
            return new Panel { Dock = DockStyle.Fill, BackColor = pageColor, Padding = new Padding(0, 0, 0, 20), AutoScroll = true };
        }

        private void ShowPage(string page)
        {
            pageHost.Controls.Clear();
            Panel selected;
            Button selectedNav;
            switch (page)
            {
                case "scan": selected = scanPage; selectedNav = scanNav; break;
                case "quarantine": selected = quarantinePage; selectedNav = quarantineNav; break;
                case "updates": selected = updatesPage; selectedNav = updatesNav; break;
                case "settings": selected = settingsPage; selectedNav = settingsNav; break;
                default: selected = overviewPage; selectedNav = overviewNav; break;
            }
            pageHost.Controls.Add(selected);
            SetActiveNav(selectedNav);
            if (page == "overview")
            {
                pageTitle.Text = T("Overview", "نظرة عامة");
                pageSubtitle.Text = T("Your protection at a glance", "حالة الحماية أمامك مباشرة");
            }
            else if (page == "scan")
            {
                pageTitle.Text = T("Scan center", "مركز الفحص");
                pageSubtitle.Text = T("Inspect files with the local engine", "افحص الملفات بالمحرك المحلي");
            }
            else if (page == "quarantine")
            {
                pageTitle.Text = T("Quarantine", "العزل");
                pageSubtitle.Text = T("Review isolated items safely", "راجع العناصر المعزولة بأمان");
            }
            else if (page == "updates")
            {
                pageTitle.Text = T("Updates", "التحديثات");
                pageSubtitle.Text = T("Signed intelligence from GitHub", "استخبارات موقعة من GitHub");
            }
            else
            {
                pageTitle.Text = T("Settings", "الإعدادات");
                pageSubtitle.Text = T("Simple controls for your protection", "خيارات بسيطة لحمايتك");
            }
        }

        private void SetActiveNav(Button active)
        {
            var buttons = new[] { overviewNav, scanNav, quarantineNav, updatesNav, settingsNav };
            foreach (var button in buttons)
            {
                if (button == null) continue;
                button.BackColor = button == active ? Color.FromArgb(23, 119, 210) : sidebarColor;
                button.ForeColor = Color.White;
            }
        }

        private Button MakeNavButton(string english, string glyph)
        {
            var button = new Button { Width = 202, Height = 43, Margin = new Padding(0, 3, 0, 3), FlatStyle = FlatStyle.Flat, FlatAppearance = { BorderSize = 0 }, BackColor = sidebarColor, ForeColor = Color.FromArgb(216, 231, 244), Font = new Font("Segoe UI", 9.5F, FontStyle.Regular), TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(13, 0, 0, 0), Tag = english, Text = glyph + "   " + english, Cursor = Cursors.Hand };
            return button;
        }

        private Button MakeButton(string text, int width, int height, Color background, Color foreground)
        {
            var button = new Button { Text = text, Width = width, Height = height, FlatStyle = FlatStyle.Flat, BackColor = background, ForeColor = foreground, Font = new Font("Segoe UI", 9F, FontStyle.Bold), Cursor = Cursors.Hand, UseVisualStyleBackColor = false };
            button.FlatAppearance.BorderSize = 0;
            button.FlatAppearance.MouseOverBackColor = ControlPaint.Light(background, 0.12F);
            return button;
        }

        private void LoadActiveDatabase()
        {
            database = updater.LoadActive();
            RefreshSecurityState();
        }

        private void RefreshSecurityState()
        {
            var installed = database != null && database.Manifest != null;
            if (protectionValue == null) return;
            protectionValue.Text = installed ? T("You are protected", "أنت محمي") : T("Needs attention", "يحتاج إلى انتباه");
            protectionValue.ForeColor = installed ? safeColor : reviewColor;
            protectionDetail.Text = installed ? T("Signed intelligence is active and ready for local scans.", "الاستخبارات الموقعة نشطة وجاهزة للفحص المحلي.") : T("Install a verified intelligence database before scanning.", "ثبت حزمة استخبارات موثقة قبل بدء الفحص.");
            overviewMessage.Text = installed ? T("Protection status: healthy", "حالة الحماية: جيدة") : T("Action recommended: update intelligence", "الإجراء المقترح: تحديث الاستخبارات");
            headerStatus.Text = installed ? T("● Protected", "● محمي") : T("● Needs attention", "● يحتاج إلى انتباه");
            headerStatus.ForeColor = installed ? safeColor : reviewColor;
            var version = installed ? database.Manifest.Version : T("Not installed", "غير مثبتة");
            headerDatabase.Text = T("Intelligence " + version, "الاستخبارات " + version);
            if (databaseValue != null) databaseValue.Text = version;
            if (updateDetail != null) updateDetail.Text = installed ? T("Current signed package: " + version + ". Updates are checked automatically every 24 hours.", "الحزمة الموقعة الحالية: " + version + ". يتم التحقق من التحديث كل 24 ساعة تلقائيًا.") : T("No verified package is installed yet. Run an update to activate cloud indicators.", "لم يتم تثبيت حزمة موثقة بعد. نفذ تحديثًا لتفعيل مؤشرات السحابة.");
        }

        private async Task UpdateAsync()
        {
            if (busy) return;
            SetBusy(true);
            try
            {
                if (statusLabel != null) statusLabel.Text = T("Downloading and verifying signed intelligence...", "جارٍ تنزيل الاستخبارات الموقعة والتحقق منها...");
                var result = await updater.UpdateAsync(CancellationToken.None);
                database = updater.LoadActive();
                RefreshSecurityState();
                if (statusLabel != null) statusLabel.Text = result.Updated ? T("Update completed safely. " + result.Detail, "اكتمل التحديث بأمان. " + result.Detail) : T("No update installed. " + result.Detail, "لم يتم تثبيت تحديث. " + result.Detail);
            }
            catch (Exception ex)
            {
                if (statusLabel != null) statusLabel.Text = T("Update failed safely: " + ex.Message, "فشل التحديث بأمان: " + ex.Message);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private async Task ScanAsync()
        {
            if (busy) return;
            var target = targetBox == null ? string.Empty : targetBox.Text.Trim();
            if (target.Length == 0 || (!File.Exists(target) && !Directory.Exists(target)))
            {
                MessageBox.Show(T("Choose an existing file or folder.", "اختر ملفًا أو مجلدًا موجودًا."), Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            SetBusy(true);
            resultsView.Items.Clear();
            progressBar.Value = 0;
            cancellation = new CancellationTokenSource();
            try
            {
                statusLabel.Text = T("Scanning conservatively; legal archives are inspected before any verdict.", "جارٍ الفحص بحذر؛ يتم تحليل الأرشيفات القانونية قبل إصدار الحكم.");
                var scanner = new FileScanner(database, ScanOptions.Default);
                var summary = await Task.Run(() => scanner.ScanPath(target, (path, count, bytes) => UpdateProgress(path, count, bytes), () => cancellation.IsCancellationRequested), cancellation.Token);
                foreach (var finding in summary.Findings.OrderByDescending(x => x.Severity).ThenBy(x => x.Path, StringComparer.OrdinalIgnoreCase))
                {
                    var item = new ListViewItem(SeverityText(finding.Severity));
                    item.SubItems.Add(finding.Path);
                    item.SubItems.Add(finding.Reason);
                    item.SubItems.Add(finding.Confidence + "%");
                    item.ForeColor = finding.Severity >= FindingSeverity.Suspicious ? dangerColor : textColor;
                    resultsView.Items.Add(item);
                }
                filesValue.Text = summary.ScannedFiles.ToString();
                threatsValue.Text = summary.ThreatFiles.ToString();
                reviewsValue.Text = summary.ReviewFiles.ToString();
                lastScanValue.Text = DateTime.Now.ToString("g");
                statusLabel.Text = T("Scan finished: " + summary.ScannedFiles + " files, " + summary.ThreatFiles + " threats, " + summary.ReviewFiles + " reviews.", "انتهى الفحص: " + summary.ScannedFiles + " ملفًا، " + summary.ThreatFiles + " تهديدات، " + summary.ReviewFiles + " للمراجعة.");
                progressBar.Value = 100;
            }
            catch (OperationCanceledException)
            {
                statusLabel.Text = T("Scan cancelled.", "تم إلغاء الفحص.");
            }
            catch (Exception ex)
            {
                statusLabel.Text = T("Scan stopped safely: " + ex.Message, "توقف الفحص بأمان: " + ex.Message);
            }
            finally
            {
                if (cancellation != null) cancellation.Dispose();
                cancellation = null;
                SetBusy(false);
            }
        }

        private void UpdateProgress(string path, int count, long bytes)
        {
            if (IsDisposed) return;
            BeginInvoke((Action)(() =>
            {
                if (IsDisposed) return;
                progressBar.Value = Math.Min(99, Math.Max(0, count % 100));
                statusLabel.Text = T("Scanning " + count + " files: " + path, "جارٍ فحص " + count + " ملف: " + path);
            }));
        }

        private void RefreshQuarantine()
        {
            if (quarantineView == null) return;
            quarantineView.Items.Clear();
            var service = new QuarantineService(storageRoot);
            var records = service.List();
            quarantineCount.Text = T(records.Count + " isolated items", records.Count + " عناصر معزولة");
            foreach (var record in records)
            {
                var item = new ListViewItem(record.CreatedUtc.ToLocalTime().ToString("g"));
                item.SubItems.Add(record.OriginalPath);
                item.SubItems.Add(record.Sha256);
                item.Tag = record.Id;
                quarantineView.Items.Add(item);
            }
        }

        private void RestoreSelectedQuarantine()
        {
            if (quarantineView.SelectedItems.Count == 0)
            {
                MessageBox.Show(T("Select an isolated item first.", "اختر عنصرًا معزولًا أولًا."), Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            try
            {
                var id = Convert.ToString(quarantineView.SelectedItems[0].Tag);
                new QuarantineService(storageRoot).Restore(id);
                RefreshQuarantine();
            }
            catch (Exception ex)
            {
                MessageBox.Show(T("Restore failed: " + ex.Message, "فشل الاسترجاع: " + ex.Message), Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void SetBusy(bool value)
        {
            busy = value;
            if (scanButton != null) scanButton.Enabled = !value;
            if (updateButton != null) updateButton.Enabled = !value;
            if (headerUpdateButton != null) headerUpdateButton.Enabled = !value;
            if (browseButton != null) browseButton.Enabled = !value;
            if (quickScanButton != null) quickScanButton.Enabled = !value;
            if (quickUpdateButton != null) quickUpdateButton.Enabled = !value;
            Cursor = value ? Cursors.WaitCursor : Cursors.Default;
        }

        private void BrowseButton_Click(object sender, EventArgs e)
        {
            using (var dialog = new FolderBrowserDialog { Description = T("Choose a folder to scan", "اختر مجلدًا لفحصه") })
            {
                if (dialog.ShowDialog(this) == DialogResult.OK) targetBox.Text = dialog.SelectedPath;
            }
        }

        private void ApplyLanguage(bool useArabic)
        {
            arabic = useArabic;
            if (overviewNav == null) return;
            overviewNav.Text = T("◉   Overview", "◉   نظرة عامة");
            scanNav.Text = T("⌕   Scan", "⌕   فحص");
            quarantineNav.Text = T("▣   Quarantine", "▣   العزل");
            updatesNav.Text = T("↻   Updates", "↻   التحديثات");
            settingsNav.Text = T("⚙   Settings", "⚙   الإعدادات");
            if (languageBox != null && languageBox.SelectedIndex != (arabic ? 1 : 0)) languageBox.SelectedIndex = arabic ? 1 : 0;
            if (browseButton != null) browseButton.Text = T("Browse", "استعراض");
            if (scanButton != null) scanButton.Text = T("Scan now", "فحص الآن");
            if (updateButton != null) updateButton.Text = T("Check for updates", "البحث عن تحديثات");
            if (headerUpdateButton != null) headerUpdateButton.Text = T("Update", "تحديث");
            if (resultsView != null)
            {
                resultsView.Columns[0].Text = T("Severity", "المستوى");
                resultsView.Columns[1].Text = T("Path", "المسار");
                resultsView.Columns[2].Text = T("Reason", "السبب");
                resultsView.Columns[3].Text = T("Confidence", "الثقة");
            }
            RightToLeft = arabic ? RightToLeft.Yes : RightToLeft.No;
            RightToLeftLayout = arabic;
            RefreshSecurityState();
        }

        private string SeverityText(FindingSeverity severity)
        {
            switch (severity)
            {
                case FindingSeverity.Confirmed: return T("Confirmed", "مؤكد");
                case FindingSeverity.Suspicious: return T("Suspicious", "مشبوه");
                case FindingSeverity.Review: return T("Review", "مراجعة");
                default: return T("Safe", "سليم");
            }
        }

        private string T(string english, string arabicText)
        {
            return arabic ? arabicText : english;
        }

        private sealed class SurfacePanel : Panel
        {
            public SurfacePanel()
            {
                SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer, true);
                BorderStyle = BorderStyle.None;
            }

            protected override void OnPaintBackground(PaintEventArgs e)
            {
                using (var brush = new SolidBrush(BackColor)) e.Graphics.FillRectangle(brush, ClientRectangle);
                using (var pen = new Pen(Color.FromArgb(226, 232, 240))) e.Graphics.DrawRectangle(pen, 0, 0, Width - 1, Height - 1);
            }
        }

        private sealed class ShieldMark : Control
        {
            public Color Accent { get; set; }

            public ShieldMark()
            {
                Accent = Color.FromArgb(23, 119, 210);
                SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer, true);
                BackColor = Color.Transparent;
            }

            protected override void OnPaint(PaintEventArgs e)
            {
                base.OnPaint(e);
                e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                var w = Math.Max(20, Width - 8);
                var h = Math.Max(24, Height - 8);
                var x = 4F;
                var y = 4F;
                using (var path = new GraphicsPath())
                {
                    path.AddBezier(x + w * 0.50F, y, x + w * 0.80F, y + h * 0.13F, x + w * 0.91F, y + h * 0.10F, x + w * 0.91F, y + h * 0.29F);
                    path.AddBezier(x + w * 0.91F, y + h * 0.29F, x + w * 0.91F, y + h * 0.66F, x + w * 0.72F, y + h * 0.86F, x + w * 0.50F, y + h);
                    path.AddBezier(x + w * 0.50F, y + h, x + w * 0.27F, y + h * 0.86F, x + w * 0.09F, y + h * 0.66F, x + w * 0.09F, y + h * 0.29F);
                    path.AddBezier(x + w * 0.09F, y + h * 0.29F, x + w * 0.09F, y + h * 0.10F, x + w * 0.20F, y + h * 0.13F, x + w * 0.50F, y);
                    using (var brush = new SolidBrush(Accent)) e.Graphics.FillPath(brush, path);
                    using (var pen = new Pen(Color.FromArgb(255, 255, 255), Math.Max(2F, Width / 15F)))
                    {
                        var points = new[] { new PointF(x + w * 0.29F, y + h * 0.51F), new PointF(x + w * 0.44F, y + h * 0.66F), new PointF(x + w * 0.72F, y + h * 0.37F) };
                        e.Graphics.DrawLines(pen, points);
                    }
                }
            }
        }
    }
}
