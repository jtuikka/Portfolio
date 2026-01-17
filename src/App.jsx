import "./styles.css";
import { BrowserRouter as Router, Routes, Route, Link } from "react-router-dom";
import Home from "./pages/Home";
import Languages from "./pages/Languages";
import LanguageDetail from "./pages/LanguageDetail";
import ProjectDetail from "./pages/ProjectDetail";
import { LanguageProvider } from "./context/LanguageProvider";
import { useLanguage } from "./context/LanguageContext";
import { translations } from "./translations/translations";

function AppContent() {
  const { language, toggleLanguage } = useLanguage();
  const t = translations[language];

  return (
    <div className="page">
      <header className="topbar">
        <nav className="topnav" aria-label="Main menu">
          <Link className="toplink" to="/">{t.nav.home}</Link>
          <Link className="toplink" to="/languages">{t.nav.languages}</Link>
        </nav>

        <div className="langSwitch" aria-label="Language selection">
          <button 
            className={`langBtn ${language === 'fi' ? 'isActive' : ''}`}
            onClick={toggleLanguage}
          >
            FI
          </button>
          <span className="langSep">/</span>
          <button 
            className={`langBtn ${language === 'en' ? 'isActive' : ''}`}
            onClick={toggleLanguage}
          >
            EN
          </button>
        </div>
      </header>

      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/languages" element={<Languages />} />
        <Route path="/languages/:slug" element={<LanguageDetail />} />
        <Route path="/projects/:slug" element={<ProjectDetail />} />
      </Routes>
    </div>
  );
}

export default function App() {
  return (
    <LanguageProvider>
      <Router>
        <AppContent />
      </Router>
    </LanguageProvider>
  );
}
