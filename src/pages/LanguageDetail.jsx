import { useParams, Link } from "react-router-dom";
import { useLanguage } from "../context/LanguageContext";
import { translations } from "../translations/translations";
import { getLanguages } from "../data/languages";

function slugify(name) {
  return name.toLowerCase().replace(/\s+/g, "-");
}

export default function LanguageDetail() {
  const { slug } = useParams();
  const { language } = useLanguage();
  const t = translations[language];

  const languages = getLanguages(t);

  const lang = languages.find((l) => slugify(l.name) === slug);

  if (!lang) {
    return (
      <main className="mainContent">
        <div className="rightSidebar">
          <h1>Not found</h1>
          <p>Tätä kieltä ei löytynyt.</p>
          <Link to="/languages">← Back</Link>
        </div>
      </main>
    );
  }

  return (
    <main className="mainContent">
      <div className="rightSidebar">
        <Link className="backLink" to="/languages">← {t.languages.title}</Link>

        <div className="langHeader">
          <img src={lang.icon} alt="" className="langHeaderIcon" />
          <h1 className="langHeaderTitle">{lang.name}</h1>
        </div>

        <p className="langDescription">{lang.description}</p>

        {/* myöhemmin: projektit / kokemustaso / linkit */}
      </div>
    </main>
  );
}
