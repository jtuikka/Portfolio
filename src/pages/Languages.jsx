import { useLanguage } from "../context/LanguageContext";
import { translations } from "../translations/translations";

export default function Languages() {
  const { language } = useLanguage();
  const t = translations[language];

  return (
    <main className="mainContent">
      <div className="rightSidebar">
        <div className="description">
          <h1>{t.languages.title}</h1>
          <p>
            {t.languages.description}
          </p>
        </div>
      </div>
    </main>
  );
}
