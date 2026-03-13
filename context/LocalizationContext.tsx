import React, { createContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { translations } from '../locales/translations';

export type Language = keyof typeof translations;

export const languages: { [key in Language]: string } = {
    en: 'English',
    de: 'Deutsch',
    es: 'Español',
    fr: 'Français',
    it: 'Italiano',
    ja: '日本語',
    nl: 'Nederlands',
    ru: 'Русский',
    zh: '中文',
    ar: 'العربية'
};

interface LocalizationContextType {
    t: (key: string, replacements?: { [key: string]: string | number }) => string;
    changeLanguage: (lang: Language) => void;
    currentLanguage: Language;
    languages: { [key in Language]: string };
}

export const LocalizationContext = createContext<LocalizationContextType | undefined>(undefined);

interface LocalizationProviderProps {
    children: ReactNode;
}

export const LocalizationProvider: React.FC<LocalizationProviderProps> = ({ children }) => {
    const getInitialLanguage = (): Language => {
        const savedLang = localStorage.getItem('language') as Language;
        if (savedLang && languages[savedLang]) {
            return savedLang;
        }
        const browserLang = navigator.language.split('-')[0] as Language;
        return languages[browserLang] ? browserLang : 'en';
    };

    const [currentLanguage, setCurrentLanguage] = useState<Language>(getInitialLanguage);

    useEffect(() => {
        localStorage.setItem('language', currentLanguage);
        document.documentElement.lang = currentLanguage;
        document.documentElement.dir = currentLanguage === 'ar' ? 'rtl' : 'ltr';
    }, [currentLanguage]);

    const changeLanguage = (lang: Language) => {
        if (languages[lang]) {
            setCurrentLanguage(lang);
        }
    };

    const t = useCallback((key: string, replacements: { [key: string]: string | number } = {}): string => {
        let translation = translations[currentLanguage]?.[key] || translations['en'][key] || key;
        
        Object.keys(replacements).forEach(placeholder => {
            const regex = new RegExp(`\\{${placeholder}\\}`, 'g');
            translation = translation.replace(regex, String(replacements[placeholder]));
        });

        return translation;
    }, [currentLanguage]);

    return (
        <LocalizationContext.Provider value={{ t, changeLanguage, currentLanguage, languages }}>
            {children}
        </LocalizationContext.Provider>
    );
};
