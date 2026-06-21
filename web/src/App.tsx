import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { OverviewPage }     from './pages/Overview'
import { DevicesPage }      from './pages/Devices'
import { DeviceDetailPage } from './pages/DeviceDetail'
import { ProfilesPage }     from './pages/Profiles'
import { ProfileDetailPage }from './pages/ProfileDetail'
import { GroupsPage }       from './pages/Groups'
import { CompliancePage }   from './pages/Compliance'
import { LoginPage }        from './pages/Login'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/"            element={<OverviewPage />} />
        <Route path="/devices"     element={<DevicesPage />} />
        <Route path="/devices/:id" element={<DeviceDetailPage />} />
        <Route path="/profiles"    element={<ProfilesPage />} />
        <Route path="/profiles/:id" element={<ProfileDetailPage />} />
        <Route path="/groups"      element={<GroupsPage />} />
        <Route path="/compliance"  element={<CompliancePage />} />
        {/* Catch-all → overview */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
