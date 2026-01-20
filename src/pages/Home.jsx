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
            <p>{t.common.name}</p>
          </div>
          <div className="profileText">
            <p>{t.home.degree}</p>
          </div>
          <div className="contactActions">
            <a className="contactBtn contactBtn--reveal" href={`tel:${t.home.phoneNumber.replace(/\s/g, '')}`}>
              <span className="contactLabel">
                <span className="contactIcon" aria-hidden="true">
                  <svg viewBox="0 0 24 24" width="16" height="16">
                    <path
                      fill="currentColor"
                      d="M6.62 10.79a15.05 15.05 0 0 0 6.59 6.59l2.2-2.2a1 1 0 0 1 1.01-.24c1.12.37 2.33.57 3.58.57a1 1 0 0 1 1 1V20a1 1 0 0 1-1 1C10.07 21 3 13.93 3 5a1 1 0 0 1 1-1h3.5a1 1 0 0 1 1 1c0 1.25.2 2.46.57 3.58a1 1 0 0 1-.24 1.01l-2.21 2.2z"
                    />
                  </svg>
                </span>
                {t.home.phone}
              </span>
              <span className="contactValue">{t.home.phoneNumber}</span>
            </a>

            <a className="contactBtn contactBtn--reveal" href={`mailto:${t.home.emailAddress}`}>
              <span className="contactLabel">
                <span className="contactIcon" aria-hidden="true">
                  <svg viewBox="0 0 24 24" width="16" height="16">
                    <path
                      fill="currentColor"
                      d="M20 4H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2zm0 4-8 5-8-5V6l8 5 8-5v2z"
                    />
                  </svg>
                </span>
                {t.home.email}
              </span>
              <span className="contactValue">{t.home.emailAddress}</span>
            </a>

            <a
              className="contactBtn"
              href="https://github.com/jtuikka"
              target="_blank"
              rel="noreferrer"
            >
              <span className="contactLabel">
                <span className="contactIcon" aria-hidden="true">
                  <svg viewBox="0 0 24 24" width="16" height="16">
                    <path
                      fill="currentColor"
                      d="M12 .5a12 12 0 0 0-3.79 23.4c.6.11.82-.26.82-.58v-2.04c-3.34.73-4.04-1.61-4.04-1.61-.55-1.39-1.34-1.76-1.34-1.76-1.09-.75.08-.74.08-.74 1.2.09 1.83 1.23 1.83 1.23 1.07 1.83 2.81 1.3 3.5.99.11-.78.42-1.3.76-1.6-2.66-.3-5.46-1.33-5.46-5.93 0-1.31.47-2.38 1.23-3.22-.12-.3-.53-1.52.12-3.17 0 0 1-.32 3.3 1.23a11.5 11.5 0 0 1 6 0C17.32 3.4 18.32 3.7 18.32 3.7c.65 1.65.24 2.87.12 3.17.76.84 1.23 1.91 1.23 3.22 0 4.61-2.8 5.62-5.47 5.92.43.38.81 1.11.81 2.24v3.32c0 .32.22.69.82.58A12 12 0 0 0 12 .5z"
                    />
                  </svg>
                </span>
                {t.home.github}
              </span>
            </a>

            <a
              className="contactBtn"
              href="https://www.linkedin.com/in/janne-tuikka/"
              target="_blank"
              rel="noreferrer"
            >
              <span className="contactLabel">
                <span className="contactIcon" aria-hidden="true">
                  <svg viewBox="0 0 24 24" width="16" height="16">
                    <path
                      fill="currentColor"
                      d="M4.98 3.5C4.98 4.88 3.87 6 2.5 6S0 4.88 0 3.5 1.12 1 2.5 1 4.98 2.12 4.98 3.5zM0 8h5v16H0V8zm7.5 0H12v2.2h.07c.63-1.2 2.17-2.47 4.47-2.47 4.78 0 5.66 3.15 5.66 7.25V24h-5v-7.96c0-1.9-.03-4.34-2.64-4.34-2.64 0-3.04 2.06-3.04 4.2V24h-5V8z"
                    />
                  </svg>
                </span>
                {t.home.linkedin}
              </span>
            </a>
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
                    alt={`${tool.name} ${t.common.logo}`}
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
          <h2 className="toolsTitle">{t.home.educationTitle}</h2>
          <div className="infoBox">{t.home.extraBoxText}</div>
          <h2 className="toolsTitle">{t.home.languagesTitle}</h2>
          <div className="infoBox">{t.home.extraBox2}</div>
        </aside>
      </section>
    </>
  );
}
