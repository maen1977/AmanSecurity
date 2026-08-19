using MaenShield.Core;
using MaenShield.Infrastructure;
using System;
using System.Drawing;
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
        private ThreatDatabaseSnapshot database;
        private CancellationTokenSource cancellation;
        private TextBox targetBox;
        private Button scanButton;
        private Button updateButton;
        private Button browseButton;
        private ComboBox languageBox;
        private Label statusLabel;
        private Label databaseLabel;
        private ProgressBar progressBar;
        private ListView resultsView;
        private bool arabic;

        public MainForm(string storageRoot, int appVersionCode, string appVersionName)
        {
            updater = new CloudUpdateService(storageRoot, appVersionCode, CloudUpdateService.DefaultBaseUrl);
            arabic = System.Globalization.CultureInfo.CurrentUICulture.Name.StartsWith("ar", StringComparison.OrdinalIgnoreCase);
            InitializeUi();
            LoadActiveDatabase();
        }

        private void InitializeUi()
        {
            Text = "Maen Shield for Windows";
            MinimumSize = new Size(820, 520);
            Size = new Size(1050, 680);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Segoe UI", 9F);
            BackColor = Color.White;

            var header = new Panel { Dock = DockStyle.Top, Height = 105, BackColor = Color.FromArgb(20, 42, 68), Padding = new Padding(18, 12, 18, 12) };
            var title = new Label { AutoSize = true, ForeColor = Color.White, Font = new Font("Segoe UI", 18F, FontStyle.Bold), Location = new Point(18, 12), Text = "Maen Shield" };
            var subtitle = new Label { AutoSize = true, ForeColor = Color.FromArgb(210, 225, 240), Location = new Point(20, 52), Text = "Free local protection with signed intelligence updates" };
            header.Controls.Add(title);
            header.Controls.Add(subtitle);
            Controls.Add(header);

            var controls = new TableLayoutPanel { Dock = DockStyle.Top, Height = 105, ColumnCount = 4, RowCount = 2, Padding = new Padding(14, 12, 14, 8) };
            controls.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            controls.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100F));
            controls.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 125F));
            controls.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110F));
            controls.RowStyles.Add(new RowStyle(SizeType.Absolute, 34F));
            controls.RowStyles.Add(new RowStyle(SizeType.Absolute, 38F));
            targetBox = new TextBox { Dock = DockStyle.Fill, Text = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) };
            browseButton = new Button { Dock = DockStyle.Fill, Text = "Browse" };
            scanButton = new Button { Dock = DockStyle.Fill, Text = "Scan", BackColor = Color.FromArgb(38, 120, 83), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            updateButton = new Button { Dock = DockStyle.Fill, Text = "Update", BackColor = Color.FromArgb(41, 94, 150), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            controls.Controls.Add(targetBox, 0, 0);
            controls.SetColumnSpan(targetBox, 2);
            controls.Controls.Add(browseButton, 2, 0);
            controls.Controls.Add(scanButton, 3, 0);
            statusLabel = new Label { Dock = DockStyle.Fill, AutoEllipsis = true, TextAlign = ContentAlignment.MiddleLeft, ForeColor = Color.FromArgb(50, 50, 50) };
            databaseLabel = new Label { Dock = DockStyle.Fill, AutoEllipsis = true, TextAlign = ContentAlignment.MiddleLeft, ForeColor = Color.FromArgb(50, 50, 50) };
            languageBox = new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList };
            languageBox.Items.AddRange(new object[] { "English", "العربية" });
            languageBox.SelectedIndex = arabic ? 1 : 0;
            controls.Controls.Add(statusLabel, 0, 1);
            controls.SetColumnSpan(statusLabel, 2);
            controls.Controls.Add(databaseLabel, 2, 1);
            controls.Controls.Add(languageBox, 3, 1);
            Controls.Add(controls);

            progressBar = new ProgressBar { Dock = DockStyle.Top, Height = 8, Style = ProgressBarStyle.Continuous, Minimum = 0, Maximum = 100, Value = 0 };
            Controls.Add(progressBar);

            resultsView = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, HideSelection = false, MultiSelect = false };
            resultsView.Columns.Add("Severity", 100);
            resultsView.Columns.Add("Path", 330);
            resultsView.Columns.Add("Reason", 430);
            resultsView.Columns.Add("Confidence", 100);
            Controls.Add(resultsView);

            browseButton.Click += BrowseButton_Click;
            scanButton.Click += async (s, e) => await ScanAsync();
            updateButton.Click += async (s, e) => await UpdateAsync();
            languageBox.SelectedIndexChanged += (s, e) => ApplyLanguage(languageBox.SelectedIndex == 1);
            FormClosing += (s, e) => { if (cancellation != null) cancellation.Cancel(); };
            ApplyLanguage(arabic);
        }

        private void LoadActiveDatabase()
        {
            database = updater.LoadActive();
            if (database == null)
            {
                statusLabel.Text = T("No verified intelligence package is installed. Run Update before scanning for cloud indicators.", "لا توجد حزمة استخبارات موثقة. اضغط تحديث قبل الفحص للاستفادة من المؤشرات السحابية.");
                databaseLabel.Text = T("Cloud database: not installed", "قاعدة السحابة: غير مثبتة");
            }
            else
            {
                databaseLabel.Text = T("Cloud database: " + database.Manifest.Version, "قاعدة السحابة: " + database.Manifest.Version);
            }
        }

        private async Task UpdateAsync()
        {
            SetBusy(true);
            try
            {
                statusLabel.Text = T("Downloading and verifying the signed intelligence package...", "جارٍ تنزيل حزمة الاستخبارات الموقعة والتحقق منها...");
                var result = await updater.UpdateAsync(CancellationToken.None);
                database = updater.LoadActive();
                if (result.Updated)
                {
                    databaseLabel.Text = T("Cloud database: " + result.Version, "قاعدة السحابة: " + result.Version);
                    statusLabel.Text = T("Update completed safely. " + result.Detail, "اكتمل التحديث بأمان. " + result.Detail);
                }
                else
                {
                    statusLabel.Text = T("No update installed. " + result.Detail, "لم يتم تثبيت تحديث. " + result.Detail);
                }
            }
            finally
            {
                SetBusy(false);
            }
        }

        private async Task ScanAsync()
        {
            var target = targetBox.Text.Trim();
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
                    item.ForeColor = finding.Severity >= FindingSeverity.Suspicious ? Color.DarkRed : Color.DarkOrange;
                    resultsView.Items.Add(item);
                }
                statusLabel.Text = T("Scan finished: " + summary.ScannedFiles + " files, " + summary.ThreatFiles + " threat findings, " + summary.ReviewFiles + " review findings.", "انتهى الفحص: " + summary.ScannedFiles + " ملفًا، " + summary.ThreatFiles + " إنذارات تهديد، " + summary.ReviewFiles + " حالات للمراجعة.");
                progressBar.Value = 100;
            }
            catch (OperationCanceledException)
            {
                statusLabel.Text = T("Scan cancelled.", "تم إلغاء الفحص.");
            }
            finally
            {
                cancellation.Dispose();
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
                progressBar.Value = count % 100;
                statusLabel.Text = T("Scanning " + count + " files: " + path, "جارٍ فحص " + count + " ملف: " + path);
            }));
        }

        private void SetBusy(bool busy)
        {
            scanButton.Enabled = !busy;
            updateButton.Enabled = !busy;
            browseButton.Enabled = !busy;
            Cursor = busy ? Cursors.WaitCursor : Cursors.Default;
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
            if (scanButton == null) return;
            browseButton.Text = T("Browse", "استعراض");
            scanButton.Text = T("Scan", "فحص");
            updateButton.Text = T("Update", "تحديث");
            resultsView.Columns[0].Text = T("Severity", "المستوى");
            resultsView.Columns[1].Text = T("Path", "المسار");
            resultsView.Columns[2].Text = T("Reason", "السبب");
            resultsView.Columns[3].Text = T("Confidence", "الثقة");
            RightToLeft = arabic ? RightToLeft.Yes : RightToLeft.No;
            RightToLeftLayout = arabic;
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
    }
}
