import { useEffect, useState } from 'react';
import { AnalysisPanel } from './components/AnalysisPanel';
import { CaseLabView } from './components/CaseLabView';
import { GuidelinesView } from './components/GuidelinesView';
import { Sidebar, type ActiveView } from './components/Sidebar';
import { ThreatLogView } from './components/ThreatLogView';
import { TopBar } from './components/TopBar';
import { INITIAL_SCAN_HISTORY } from './data/sampleCases';
import type { SampleCase, ScanRecord } from './types/phishguard';

const STORAGE_KEY = 'phishguard_ia_scans_v1';

function loadInitialScans(): ScanRecord[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return INITIAL_SCAN_HISTORY;
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed as ScanRecord[];
    }
    return INITIAL_SCAN_HISTORY;
  } catch {
    return INITIAL_SCAN_HISTORY;
  }
}

export default function App() {
  const [activeView, setActiveView] = useState<ActiveView>('analyze');
  const [scans, setScans] = useState<ScanRecord[]>(loadInitialScans);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [prefillCase, setPrefillCase] = useState<SampleCase | null>(null);
  const [resetToken, setResetToken] = useState(0);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(scans));
    } catch {
      // Ignore storage quota errors gracefully
    }
  }, [scans]);

  const handleAnalysisComplete = (newRecord: ScanRecord) => {
    setScans((prev) => [newRecord, ...prev]);
  };

  const handleDeleteScan = (id: string) => {
    setScans((prev) => prev.filter((item) => item.id !== id));
  };

  const handleLoadCaseIntoScanner = (sample: SampleCase) => {
    setPrefillCase({ ...sample });
    setActiveView('analyze');
  };

  const handleNewScan = () => {
    setPrefillCase(null);
    setResetToken((prev) => prev + 1);
    setActiveView('analyze');
  };

  return (
    <div className="flex min-h-screen bg-slate-50 text-slate-900">
      <Sidebar
        activeView={activeView}
        onSelectView={setActiveView}
        scans={scans}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar
          activeView={activeView}
          onOpenMobileMenu={() => setMobileMenuOpen(true)}
          onNewScan={handleNewScan}
        />

        <main className="flex-1 px-4 py-6 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-6xl">
            {activeView === 'analyze' && (
              <AnalysisPanel
                prefillCase={prefillCase}
                resetToken={resetToken}
                onAnalysisComplete={handleAnalysisComplete}
              />
            )}

            {activeView === 'history' && (
              <ThreatLogView
                scans={scans}
                onDeleteScan={handleDeleteScan}
                onStartNewAnalysis={handleNewScan}
              />
            )}

            {activeView === 'cases' && (
              <CaseLabView onLoadCaseIntoScanner={handleLoadCaseIntoScanner} />
            )}

            {activeView === 'guidelines' && <GuidelinesView />}
          </div>
        </main>
      </div>
    </div>
  );
}
