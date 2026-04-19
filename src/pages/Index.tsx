import { useState, useEffect, useCallback } from 'react';
import Icon from '@/components/ui/icon';

const SCANS_LIST_URL = 'https://functions.poehali.dev/7aa743c0-2da8-4916-91a8-e0c0bd9b33fc';
const SECURITY_SCAN_URL = 'https://functions.poehali.dev/1820c74a-0c1c-4817-b56d-603708d11353';

type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

interface ScanResult {
  id: number;
  scan_id: string;
  created_at: string;
  status: string;
  risk_level: RiskLevel;
  env_vars_count: number;
  secrets_found: number;
  suspicious_files: number;
  summary: Record<string, unknown>;
}

interface Stats {
  critical: number;
  high: number;
  medium: number;
  low: number;
  avg_secrets: number;
  max_secrets: number;
}

const RISK_CONFIG: Record<RiskLevel, { label: string; cls: string; bg: string; dot: string }> = {
  critical: { label: 'CRITICAL', cls: 'risk-critical', bg: 'bg-risk-critical', dot: 'bg-red-500' },
  high:     { label: 'HIGH',     cls: 'risk-high',     bg: 'bg-risk-high',     dot: 'bg-orange-500' },
  medium:   { label: 'MEDIUM',   cls: 'risk-medium',   bg: 'bg-risk-medium',   dot: 'bg-yellow-500' },
  low:      { label: 'LOW',      cls: 'risk-low',      bg: 'bg-risk-low',      dot: 'bg-green-500' },
  unknown:  { label: 'UNKNOWN',  cls: 'text-muted-foreground', bg: '', dot: 'bg-gray-500' },
};

function RiskBadge({ level }: { level: RiskLevel }) {
  const cfg = RISK_CONFIG[level] || RISK_CONFIG.unknown;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-mono font-medium border ${cfg.bg} ${cfg.cls}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  );
}

function StatCard({ label, value, sub, icon, accent }: {
  label: string; value: string | number; sub?: string;
  icon: string; accent?: string;
}) {
  return (
    <div className="bg-card border border-border rounded-lg p-5 flex flex-col gap-3 animate-slide-up hover:border-primary/30 transition-colors">
      <div className="flex items-center justify-between">
        <span className="text-xs font-mono text-muted-foreground uppercase tracking-widest">{label}</span>
        <div className={`w-8 h-8 rounded flex items-center justify-center ${accent || 'bg-muted'}`}>
          <Icon name={icon as 'Shield'} size={16} className={accent ? 'text-primary' : 'text-muted-foreground'} />
        </div>
      </div>
      <div>
        <div className="text-3xl font-mono font-semibold text-foreground">{value}</div>
        {sub && <div className="text-xs text-muted-foreground mt-1">{sub}</div>}
      </div>
    </div>
  );
}

function ScanRow({ scan, index }: { scan: ScanResult; index: number }) {
  const date = new Date(scan.created_at);
  const timeStr = date.toLocaleString('ru', { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit' });
  const summary = scan.summary as { node?: string; platform?: string } | null;

  return (
    <div
      className="grid grid-cols-[auto_1fr_auto_auto_auto_auto] gap-4 items-center px-4 py-3 border-b border-border/50 hover:bg-muted/30 transition-colors animate-slide-up"
      style={{ animationDelay: `${index * 40}ms` }}
    >
      <div className="font-mono text-xs text-muted-foreground w-6 text-right">{scan.id}</div>
      <div className="min-w-0">
        <div className="font-mono text-xs text-foreground/80 truncate">{scan.scan_id}</div>
        {summary?.node && (
          <div className="text-xs text-muted-foreground mt-0.5">{summary.node} · {summary.platform}</div>
        )}
      </div>
      <RiskBadge level={scan.risk_level} />
      <div className="text-center">
        <span className={`font-mono text-sm font-medium ${scan.secrets_found > 0 ? 'risk-high' : 'text-muted-foreground'}`}>
          {scan.secrets_found}
        </span>
        <div className="text-xs text-muted-foreground">секретов</div>
      </div>
      <div className="text-center">
        <span className="font-mono text-sm font-medium text-foreground">{scan.env_vars_count}</span>
        <div className="text-xs text-muted-foreground">env vars</div>
      </div>
      <div className="text-xs font-mono text-muted-foreground text-right">{timeStr}</div>
    </div>
  );
}

function ScanModal({ onClose, adminToken, setAdminToken, onScanComplete }: {
  onClose: () => void;
  adminToken: string;
  setAdminToken: (v: string) => void;
  onScanComplete: () => void;
}) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<null | { scan_id: string; summary: Record<string, unknown> }>(null);
  const [error, setError] = useState('');

  const runScan = async () => {
    if (!adminToken) { setError('Введите токен администратора'); return; }
    setLoading(true);
    setError('');
    try {
      const res = await fetch(SECURITY_SCAN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Admin-Token': adminToken },
      });
      if (res.status === 403) { setError('Неверный токен. Проверьте ADMIN_TOKEN в настройках.'); setLoading(false); return; }
      const data = await res.json();
      setResult(data);
      onScanComplete();
    } catch {
      setError('Ошибка соединения с сервером');
    }
    setLoading(false);
  };

  return (
    <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-card border border-border rounded-xl w-full max-w-md p-6 animate-slide-up" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-2">
            <Icon name="Radar" size={18} className="text-primary" />
            <h2 className="font-mono font-medium text-foreground">Новый скан</h2>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors">
            <Icon name="X" size={16} />
          </button>
        </div>

        {!result ? (
          <div className="space-y-4">
            <div>
              <label className="text-xs font-mono text-muted-foreground uppercase tracking-widest mb-2 block">
                Admin Token
              </label>
              <input
                type="password"
                value={adminToken}
                onChange={e => setAdminToken(e.target.value)}
                placeholder="Секретный токен..."
                className="w-full bg-muted border border-border rounded-lg px-3 py-2.5 font-mono text-sm text-foreground placeholder-muted-foreground focus:outline-none focus:border-primary/50 transition-colors"
              />
            </div>
            {error && (
              <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
                <Icon name="AlertTriangle" size={14} />
                {error}
              </div>
            )}
            <div className="bg-muted/50 rounded-lg p-3 text-xs text-muted-foreground font-mono leading-relaxed">
              Сбор данных: env vars, filesystem, network config, proc/self/status, platform.uname()
            </div>
            <button
              onClick={runScan}
              disabled={loading}
              className="w-full bg-primary text-primary-foreground rounded-lg py-2.5 font-mono text-sm font-medium hover:bg-primary/90 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <Icon name="Loader2" size={16} className="animate-spin" />
                  Сканирование...
                </>
              ) : (
                <>
                  <Icon name="Play" size={16} />
                  Запустить аудит
                </>
              )}
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-sm text-green-400 bg-green-500/10 border border-green-500/20 rounded-lg px-3 py-2">
              <Icon name="CheckCircle" size={14} />
              Скан завершён успешно
            </div>
            <div className="bg-muted rounded-lg p-4 space-y-2">
              {Object.entries(result.summary).map(([k, v]) => (
                <div key={k} className="flex justify-between text-xs font-mono">
                  <span className="text-muted-foreground">{k}</span>
                  <span className="text-foreground">{String(v)}</span>
                </div>
              ))}
            </div>
            <button
              onClick={onClose}
              className="w-full bg-muted text-foreground rounded-lg py-2.5 font-mono text-sm hover:bg-muted/70 transition-colors"
            >
              Закрыть
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

const Index = () => {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [adminToken, setAdminToken] = useState('');
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);

  const fetchScans = useCallback(async () => {
    try {
      const res = await fetch(SCANS_LIST_URL);
      const data = await res.json();
      setScans(data.scans || []);
      setStats(data.stats || null);
      setTotal(data.total || 0);
      setLastUpdate(new Date());
    } catch (_err) {
      // network error, ignore
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 30000);
    return () => clearInterval(interval);
  }, [fetchScans]);

  const handleScanComplete = () => {
    setTimeout(fetchScans, 1000);
  };

  const riskDistribution = stats ? [
    { level: 'critical' as RiskLevel, count: stats.critical },
    { level: 'high' as RiskLevel, count: stats.high },
    { level: 'medium' as RiskLevel, count: stats.medium },
    { level: 'low' as RiskLevel, count: stats.low },
  ] : [];

  const totalRisk = riskDistribution.reduce((a, b) => a + b.count, 0);

  return (
    <div className="min-h-screen bg-background grid-bg">
      {showModal && (
        <ScanModal
          onClose={() => setShowModal(false)}
          adminToken={adminToken}
          setAdminToken={setAdminToken}
          onScanComplete={handleScanComplete}
        />
      )}

      <div className="max-w-6xl mx-auto px-6 py-8">
        {/* Header */}
        <header className="flex items-center justify-between mb-10 animate-fade-in">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-primary/20 border border-primary/30 flex items-center justify-center">
              <Icon name="Shield" size={16} className="text-primary" />
            </div>
            <div>
              <h1 className="font-mono font-semibold text-foreground tracking-tight">CloudAudit</h1>
              <p className="text-xs text-muted-foreground font-mono">Security Intelligence Platform</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            {lastUpdate && (
              <span className="text-xs font-mono text-muted-foreground hidden sm:block">
                Обновлено: {lastUpdate.toLocaleTimeString('ru')}
              </span>
            )}
            <div className="flex items-center gap-1.5 text-xs font-mono text-primary">
              <span className="w-2 h-2 rounded-full bg-primary scan-pulse" />
              LIVE
            </div>
            <button
              onClick={() => setShowModal(true)}
              className="flex items-center gap-2 bg-primary text-primary-foreground px-4 py-2 rounded-lg text-sm font-mono font-medium hover:bg-primary/90 transition-colors"
            >
              <Icon name="Plus" size={14} />
              Новый скан
            </button>
          </div>
        </header>

        {/* Stats */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <StatCard label="Всего сканов" value={total} icon="Activity" sub="за всё время" accent="bg-primary/10" />
          <StatCard label="Найдено секретов" value={stats?.max_secrets ?? 0} icon="Key" sub={`макс. в одном скане`} />
          <StatCard label="Критических" value={stats?.critical ?? 0} icon="AlertOctagon" sub="требуют внимания" />
          <StatCard label="Чистых" value={stats?.low ?? 0} icon="ShieldCheck" sub="с низким риском" accent="bg-primary/10" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          {/* Risk Distribution */}
          <div className="bg-card border border-border rounded-lg p-5 animate-slide-up" style={{ animationDelay: '100ms' }}>
            <div className="flex items-center gap-2 mb-5">
              <Icon name="PieChart" size={14} className="text-muted-foreground" />
              <h2 className="text-xs font-mono text-muted-foreground uppercase tracking-widest">Распределение рисков</h2>
            </div>
            {totalRisk === 0 ? (
              <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                <Icon name="Database" size={32} className="mb-3 opacity-30" />
                <p className="text-xs font-mono">Нет данных</p>
              </div>
            ) : (
              <div className="space-y-3">
                {riskDistribution.map(({ level, count }) => {
                  const cfg = RISK_CONFIG[level];
                  const pct = totalRisk > 0 ? Math.round((count / totalRisk) * 100) : 0;
                  return (
                    <div key={level}>
                      <div className="flex justify-between items-center mb-1">
                        <span className={`text-xs font-mono ${cfg.cls}`}>{cfg.label}</span>
                        <span className="text-xs font-mono text-muted-foreground">{count} · {pct}%</span>
                      </div>
                      <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-700 ${level === 'critical' ? 'bg-red-500' : level === 'high' ? 'bg-orange-500' : level === 'medium' ? 'bg-yellow-500' : 'bg-green-500'}`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Quick info */}
          <div className="lg:col-span-2 bg-card border border-border rounded-lg p-5 animate-slide-up" style={{ animationDelay: '150ms' }}>
            <div className="flex items-center gap-2 mb-5">
              <Icon name="Info" size={14} className="text-muted-foreground" />
              <h2 className="text-xs font-mono text-muted-foreground uppercase tracking-widest">Как это работает</h2>
            </div>
            <div className="grid grid-cols-2 gap-4">
              {[
                { icon: 'Terminal', title: 'ENV Variables', desc: 'Анализ переменных окружения на наличие секретов и токенов' },
                { icon: 'FolderSearch', title: 'Filesystem', desc: 'Проверка ключевых директорий на подозрительные файлы' },
                { icon: 'Network', title: 'Network Config', desc: 'resolv.conf, /etc/hosts — сетевые настройки среды' },
                { icon: 'Cpu', title: 'Runtime Info', desc: 'platform.uname(), /proc/self/status — информация о процессе' },
              ].map(({ icon, title, desc }) => (
                <div key={title} className="flex gap-3">
                  <div className="w-7 h-7 rounded bg-muted flex items-center justify-center flex-shrink-0 mt-0.5">
                    <Icon name={icon as 'Terminal'} size={14} className="text-primary" />
                  </div>
                  <div>
                    <div className="text-xs font-mono font-medium text-foreground mb-0.5">{title}</div>
                    <div className="text-xs text-muted-foreground leading-relaxed">{desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Scans Table */}
        <div className="bg-card border border-border rounded-lg overflow-hidden animate-slide-up" style={{ animationDelay: '200ms' }}>
          <div className="flex items-center justify-between px-4 py-3 border-b border-border">
            <div className="flex items-center gap-2">
              <Icon name="List" size={14} className="text-muted-foreground" />
              <h2 className="text-xs font-mono text-muted-foreground uppercase tracking-widest">
                Последние сканы
              </h2>
            </div>
            <span className="text-xs font-mono text-muted-foreground">{total} всего</span>
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-16">
              <div className="flex items-center gap-3 text-muted-foreground">
                <Icon name="Loader2" size={18} className="animate-spin" />
                <span className="text-sm font-mono">Загрузка...</span>
              </div>
            </div>
          ) : scans.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
              <Icon name="ShieldOff" size={40} className="mb-4 opacity-20" />
              <p className="text-sm font-mono mb-1">Сканов пока нет</p>
              <p className="text-xs">Нажмите «Новый скан» чтобы начать аудит</p>
            </div>
          ) : (
            <div>
              <div className="grid grid-cols-[auto_1fr_auto_auto_auto_auto] gap-4 px-4 py-2 border-b border-border/50 bg-muted/20">
                {['#', 'Scan ID', 'Риск', 'Секреты', 'ENV', 'Время'].map(h => (
                  <span key={h} className="text-xs font-mono text-muted-foreground uppercase tracking-wider">{h}</span>
                ))}
              </div>
              {scans.map((scan, i) => (
                <ScanRow key={scan.id} scan={scan} index={i} />
              ))}
            </div>
          )}
        </div>

        <footer className="mt-8 text-center text-xs font-mono text-muted-foreground opacity-40">
          CloudAudit · Security Intelligence Platform · {new Date().getFullYear()}
        </footer>
      </div>
    </div>
  );
};

export default Index;