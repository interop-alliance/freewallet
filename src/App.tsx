import { lazy, Suspense } from 'react'
import { Route, Routes } from 'react-router'
import { LandingPage } from '@/pages/LandingPage'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import { RouteFallback } from '@/components/RouteFallback'

// LandingPage and ProtectedRoute are eager: LandingPage is the lightweight
// unauthenticated entry point, and ProtectedRoute is a tiny auth gate. Every
// other route is lazily code-split so its (often heavy) dependencies — rxdb,
// jsonld, verifier-core, qr-scanner — stay out of the initial bundle.
const LoginPage = lazy(() =>
  import('@/pages/auth/LoginPage').then(m => ({ default: m.LoginPage }))
)
const SignupPage = lazy(() =>
  import('@/pages/auth/SignupPage').then(m => ({ default: m.SignupPage }))
)
const GuestLoginPage = lazy(() =>
  import('@/pages/auth/GuestLoginPage').then(m => ({
    default: m.GuestLoginPage
  }))
)
const LogoutPage = lazy(() =>
  import('@/pages/auth/LogoutPage').then(m => ({ default: m.LogoutPage }))
)
const WalletGetPage = lazy(() =>
  import('@/pages/chapi/WalletGetPage').then(m => ({
    default: m.WalletGetPage
  }))
)
const WalletStorePage = lazy(() =>
  import('@/pages/chapi/WalletStorePage').then(m => ({
    default: m.WalletStorePage
  }))
)
const DashboardPage = lazy(() =>
  import('@/pages/dashboard/DashboardPage').then(m => ({
    default: m.DashboardPage
  }))
)
const ContactsPage = lazy(() =>
  import('@/pages/dashboard/ContactsPage').then(m => ({
    default: m.ContactsPage
  }))
)
const ContactDetailPage = lazy(() =>
  import('@/pages/dashboard/ContactDetailPage').then(m => ({
    default: m.ContactDetailPage
  }))
)
const StoragePage = lazy(() =>
  import('@/pages/dashboard/StoragePage').then(m => ({
    default: m.StoragePage
  }))
)
const CollectionContentsPage = lazy(() =>
  import('@/pages/dashboard/CollectionContentsPage').then(m => ({
    default: m.CollectionContentsPage
  }))
)
const CollectionResourcePage = lazy(() =>
  import('@/pages/dashboard/CollectionResourcePage').then(m => ({
    default: m.CollectionResourcePage
  }))
)
const ApplicationsPage = lazy(() =>
  import('@/pages/dashboard/ApplicationsPage').then(m => ({
    default: m.ApplicationsPage
  }))
)
const ApplicationDetailPage = lazy(() =>
  import('@/pages/dashboard/ApplicationDetailPage').then(m => ({
    default: m.ApplicationDetailPage
  }))
)
const HistoryPage = lazy(() =>
  import('@/pages/dashboard/HistoryPage').then(m => ({
    default: m.HistoryPage
  }))
)
const SettingsPage = lazy(() =>
  import('@/pages/dashboard/SettingsPage').then(m => ({
    default: m.SettingsPage
  }))
)
const CredentialDetailPage = lazy(() =>
  import('@/pages/dashboard/CredentialDetailPage').then(m => ({
    default: m.CredentialDetailPage
  }))
)
const IssuerDetailPage = lazy(() =>
  import('@/pages/dashboard/IssuerDetailPage').then(m => ({
    default: m.IssuerDetailPage
  }))
)
const AddCredentialPage = lazy(() =>
  import('@/pages/dashboard/AddCredentialPage').then(m => ({
    default: m.AddCredentialPage
  }))
)
const AcceptCredentialsPage = lazy(() =>
  import('@/pages/dashboard/AcceptCredentialsPage').then(m => ({
    default: m.AcceptCredentialsPage
  }))
)
const DocsPage = lazy(() =>
  import('@/pages/dashboard/DocsPage').then(m => ({ default: m.DocsPage }))
)
const NotFoundPage = lazy(() =>
  import('@/pages/NotFoundPage').then(m => ({ default: m.NotFoundPage }))
)

function App() {
  return (
    <Suspense fallback={<RouteFallback />}>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/signup" element={<SignupPage />} />
        <Route path="/guest-login" element={<GuestLoginPage />} />
        <Route path="/logout" element={<LogoutPage />} />

        {/* CHAPI wallet UI — no ProtectedRoute, runs in a CHAPI-managed popup */}
        <Route path="/wallet/get" element={<WalletGetPage />} />
        <Route path="/wallet/store" element={<WalletStorePage />} />

        <Route element={<ProtectedRoute />}>
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/contacts" element={<ContactsPage />} />
          <Route path="/storage" element={<StoragePage />} />
          <Route
            path="/storage/collections/:collectionId"
            element={<CollectionContentsPage />}
          />
          <Route
            path="/storage/collections/:collectionId/resources/:resourceId"
            element={<CollectionResourcePage />}
          />
          <Route path="/contacts/:contactId" element={<ContactDetailPage />} />
          <Route path="/applications" element={<ApplicationsPage />} />
          <Route
            path="/applications/:cid"
            element={<ApplicationDetailPage />}
          />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/credential/:cid" element={<CredentialDetailPage />} />
          <Route
            path="/credential/:cid/issuer"
            element={<IssuerDetailPage />}
          />
          <Route path="/add-credential" element={<AddCredentialPage />} />
          <Route
            path="/accept-credentials"
            element={<AcceptCredentialsPage />}
          />
        </Route>

        <Route path="/docs/:fileName" element={<DocsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Suspense>
  )
}

export default App
