import { lazy, Suspense } from 'react'
import type { ComponentType } from 'react'
import { Route, Routes } from 'react-router'
import { LandingPage } from '@/pages/LandingPage'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import { RouteFallback } from '@/components/RouteFallback'

/**
 * `React.lazy` over a module's named export. The dynamic `import()` call stays
 * a literal at each call site so the bundler can still statically see it and
 * split the chunk.
 *
 * @param load {Function}   the dynamic import
 * @param name {string}     the exported component's name
 * @returns {LazyExoticComponent}
 */
function lazyNamed<
  Name extends string,
  Module extends Record<Name, ComponentType<unknown>>
>(load: () => Promise<Module>, name: Name) {
  return lazy(async () => ({ default: (await load())[name] }))
}

// LandingPage and ProtectedRoute are eager: LandingPage is the lightweight
// unauthenticated entry point, and ProtectedRoute is a tiny auth gate. Every
// other route is lazily code-split so its (often heavy) dependencies -- rxdb,
// jsonld, verifier-core, qr-scanner -- stay out of the initial bundle.
const LoginPage = lazyNamed(() => import('@/pages/auth/LoginPage'), 'LoginPage')
const SignupPage = lazyNamed(
  () => import('@/pages/auth/SignupPage'),
  'SignupPage'
)
const RecoverPage = lazyNamed(
  () => import('@/pages/auth/RecoverPage'),
  'RecoverPage'
)
const GuestLoginPage = lazyNamed(
  () => import('@/pages/auth/GuestLoginPage'),
  'GuestLoginPage'
)
const LogoutPage = lazyNamed(
  () => import('@/pages/auth/LogoutPage'),
  'LogoutPage'
)
const WalletGetPage = lazyNamed(
  () => import('@/pages/chapi/WalletGetPage'),
  'WalletGetPage'
)
const WalletStorePage = lazyNamed(
  () => import('@/pages/chapi/WalletStorePage'),
  'WalletStorePage'
)
const DashboardPage = lazyNamed(
  () => import('@/pages/dashboard/DashboardPage'),
  'DashboardPage'
)
const ContactsPage = lazyNamed(
  () => import('@/pages/dashboard/ContactsPage'),
  'ContactsPage'
)
const ContactDetailPage = lazyNamed(
  () => import('@/pages/dashboard/ContactDetailPage'),
  'ContactDetailPage'
)
const ContactFormPage = lazyNamed(
  () => import('@/pages/dashboard/ContactFormPage'),
  'ContactFormPage'
)
const ContactHistoryPage = lazyNamed(
  () => import('@/pages/dashboard/ContactHistoryPage'),
  'ContactHistoryPage'
)
const StoragePage = lazyNamed(
  () => import('@/pages/dashboard/StoragePage'),
  'StoragePage'
)
const CollectionContentsPage = lazyNamed(
  () => import('@/pages/dashboard/CollectionContentsPage'),
  'CollectionContentsPage'
)
const CollectionResourcePage = lazyNamed(
  () => import('@/pages/dashboard/CollectionResourcePage'),
  'CollectionResourcePage'
)
const ApplicationsPage = lazyNamed(
  () => import('@/pages/dashboard/ApplicationsPage'),
  'ApplicationsPage'
)
const ApplicationDetailPage = lazyNamed(
  () => import('@/pages/dashboard/ApplicationDetailPage'),
  'ApplicationDetailPage'
)
const HistoryPage = lazyNamed(
  () => import('@/pages/dashboard/HistoryPage'),
  'HistoryPage'
)
const SettingsPage = lazyNamed(
  () => import('@/pages/dashboard/SettingsPage'),
  'SettingsPage'
)
const CredentialDetailPage = lazyNamed(
  () => import('@/pages/dashboard/CredentialDetailPage'),
  'CredentialDetailPage'
)
const IssuerDetailPage = lazyNamed(
  () => import('@/pages/dashboard/IssuerDetailPage'),
  'IssuerDetailPage'
)
const AddCredentialPage = lazyNamed(
  () => import('@/pages/dashboard/AddCredentialPage'),
  'AddCredentialPage'
)
const AcceptCredentialsPage = lazyNamed(
  () => import('@/pages/dashboard/AcceptCredentialsPage'),
  'AcceptCredentialsPage'
)
const DocsPage = lazyNamed(
  () => import('@/pages/dashboard/DocsPage'),
  'DocsPage'
)
const NotFoundPage = lazyNamed(
  () => import('@/pages/NotFoundPage'),
  'NotFoundPage'
)

function App() {
  return (
    <Suspense fallback={<RouteFallback />}>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/signup" element={<SignupPage />} />
        <Route path="/recover" element={<RecoverPage />} />
        <Route path="/guest-login" element={<GuestLoginPage />} />
        <Route path="/logout" element={<LogoutPage />} />

        {/* CHAPI wallet UI -- no ProtectedRoute, runs in a CHAPI-managed popup */}
        <Route path="/wallet/get" element={<WalletGetPage />} />
        <Route path="/wallet/store" element={<WalletStorePage />} />

        <Route element={<ProtectedRoute />}>
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/contacts" element={<ContactsPage />} />
          <Route path="/contacts/new" element={<ContactFormPage />} />
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
          <Route
            path="/contacts/:contactId/edit"
            element={<ContactFormPage />}
          />
          <Route
            path="/contacts/:contactId/history"
            element={<ContactHistoryPage />}
          />
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
