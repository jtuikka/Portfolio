import { useParams, Link } from "react-router-dom";
import { useLocation, useNavigate } from "react-router-dom";
import { useLanguage } from "../context/LanguageContext";
import { translations } from "../translations/translations";
import { getLanguages } from "../data/languages";

function slugify(id) {
  return id.toLowerCase().replace(/\s+/g, "-");
}

export default function LanguageDetail() {
  const { slug } = useParams();
  const { language } = useLanguage();
  const t = translations[language];

  const location = useLocation();
  const navigate = useNavigate();

  const languages = getLanguages(t);

  const lang = languages.find((l) => slugify(l.id) === slug);

  const handleBack = () => {
    if (location.state?.from) navigate(-1);
    else navigate("/languages");
  };


  if (!lang) {
    return (
      <main className="mainContent">
        <div className="rightSidebar">
          <h1>Not found</h1>
          <p>Tätä kieltä ei löytynyt.</p>
          <button
            className="backLink"
            type="button"
            onClick={() => {
              if (location.state?.from) navigate(-1);
              else navigate("/languages");
            }}
          >
            ← Back
          </button>
        </div>
      </main>
    );
  }

  return (
    <main className="mainContent">
      <div className="rightSidebar">
        <button className="backLink" type="button" onClick={handleBack}>
          ← {t.languages.title}
        </button>

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
