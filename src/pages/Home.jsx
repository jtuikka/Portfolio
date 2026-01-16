import LanguagesCarousel from "../components/LanguagesCarousel";
import { getLanguages } from "../data/languages";
import { getTools } from "../data/tools";
import { useLanguage } from "../context/LanguageContext";
import { translations } from "../translations/translations";

export default function Home() {
  const { language } = useLanguage();
  const t = translations[language];
  const languages = getLanguages(t);
  const tools = getTools(t);

  return (
    <>
      <main className="mainContent">
        <aside className="leftSidebar">
          <div className="profileImage"></div>
          <div className="nameText">
            <p>Janne Tuikka</p>
          </div>
          <div className="profileText">
            <p>{t.home.degree}</p>
          </div>
        </aside>
        <aside className="rightSidebar">
          <div className="description">
            <h1>{t.home.welcomeTitle}</h1>
            <p>
              {t.home.welcomeText}
            </p>
          </div>
        </aside>
      </main>
      
      <section className="skillsSection">
        <h2 className="skillsTitle">{t.home.programmingLanguagesTitle}</h2>
        <LanguagesCarousel items={languages} key={language} />
      </section>
      
      <section className="extrasSection">
        <div className="toolsSection">
          <h2 className="toolsTitle">{t.home.toolsTitle}</h2>
          <ul className="toolsList">
            {tools.map((tool) => (
              <li className="toolItem" key={tool.name}>
                <div className="toolMeta">
                  <img
                    src={tool.icon}
                    alt={`${tool.name} logo`}
                    className="toolIcon"
                    loading="lazy"
                  />
                  <span className="toolName">{tool.name}</span>
                </div>
                <p className="toolDescription">{tool.description}</p>
              </li>
            ))}
          </ul>
        </div>

        <aside className="extrasRight">
          <div className="infoBox">{t.home.extraBoxText}</div>
          <div className="infoBox">{t.home.extraBox2}</div>
        </aside>
      </section>
    </>
  );
}
