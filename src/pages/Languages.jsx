import { Link } from "react-router-dom";
import { useLanguage } from "../context/LanguageContext";
import { translations } from "../translations/translations";
import { getLanguages } from "../data/languages";

export default function Languages() {
  const { language } = useLanguage();
  const t = translations[language];
  const languages = getLanguages(t);

function slugify(name) {
  return name.toLowerCase().replace(/\s+/g, "-");
}

  return (
    <main className="pageContent">
        <h1 className="languagesTitle">{t.languages.title}</h1>
        <div className="languagesGrid">
          {languages.map((lang) => (
            <Link
              key={lang.name}
              to={`/languages/${slugify(lang.name)}`}
              className="languageCard"
              aria-label={`Open ${lang.name}`}
            >
              <img
                src={lang.icon}
                alt={`${lang.name} icon`}
                className="languageIcon"
                loading="lazy"
              />
              <div className="languageName">{lang.name}</div>
            </Link>
          ))}
        </div>
        <h1 className="projectsTitle">{t.languages.title2}</h1>
    </main>
  );
}
