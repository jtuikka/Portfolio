import { useState } from 'react';
import { LanguageContext } from './LanguageContext';

export function LanguageProvider({ children }) {
  const [language, setLanguage] = useState('fi');

  const toggleLanguage = () => {
    setLanguage(prev => prev === 'fi' ? 'en' : 'fi');
  };

  return (
    <LanguageContext.Provider value={{ language, toggleLanguage }}>
      {children}
    </LanguageContext.Provider>
  );
}
