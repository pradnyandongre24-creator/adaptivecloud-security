// frontend/src/App.tsx
import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ToastProvider } from '@/components/ui/Toast';
import { Layout } from '@/components/layout/Layout';
import { useAuthStore } from '@/store/authStore';

// 4 core pages
import LoginPage from '@/pages/LoginPage';
import AttackDetectionPage from '@/pages/AttackDetectionPage';
import RcaPage from '@/pages/RcaPage';
import SelfHealingPage from '@/pages/SelfHealingPage';
import PredictiveMaintenancePage from '@/pages/PredictiveMaintenancePage';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5000,
    },
  },
});

function RequireAuth({ children }: { children: React.ReactNode }) {
  const token = useAuthStore((s) => s.token || s.accessToken);
  if (!token) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            element={
              <RequireAuth>
                <Layout />
              </RequireAuth>
            }
          >
            <Route path="/" element={<AttackDetectionPage />} />
            <Route path="/rca" element={<RcaPage />} />
            <Route path="/healing" element={<SelfHealingPage />} />
            <Route path="/maintenance" element={<PredictiveMaintenancePage />} />
            {/* Legacy redirects */}
            <Route path="/detections" element={<Navigate to="/" replace />} />
            <Route path="/monitoring" element={<Navigate to="/" replace />} />
            <Route path="/responses" element={<Navigate to="/healing" replace />} />
            <Route path="/predictions" element={<Navigate to="/maintenance" replace />} />
            <Route path="/learning" element={<Navigate to="/" replace />} />
            <Route path="/reports" element={<Navigate to="/" replace />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </ToastProvider>
    </QueryClientProvider>
  );
}
