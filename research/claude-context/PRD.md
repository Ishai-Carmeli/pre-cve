# Product Requirements & Specifications

## The Problem

Open-source packages suffer from the problem of “silent fixes” and “negative-day window” which can expose package users to security vulnerabilities.

A silent fix is a situation in which an open-source package maintainer approves a pull request to the main branch that appears to be a bug fix, but is a fix of security vulnerability \- the fix stays undetected.

A negative day window is when a maintainer releases a build with a security fix, and wants to alert their users \- but it can take days for vulnerability to appear in the advisory databases from which dependabot and their users read.

בשני המקרים, הזמן שעובר בין הרגע שבו התיקון מופיע באופן פומבי ועד הרגע שבו משתמשים מקבלים התרעה / תיקון, הוא חלון הזדמנויות שתוקפים יכולים לנצל. זאת על ידי התבוננות בתיקון, וללמוד דרכו את החולשה בגרסה הנוכחית שהגרסה החדשה מתקנת ומשתמשי החבילה עדיין תלויים בהם. 

# Solution:

PreCVE detects security fixes in PyPI packages during the negative-day window and alerts only the projects they affect.

1. **Monitor:** continuously track new commits in the GitHub repositories of PyPI packages.  
2. **Detect:** an LLM-based detector flags commits that are likely security fixes and identifies which   
3. functions they change.  
4. **Share:** each commit is analyzed once, and the result serves every project that depends on that package, so cost grows with commit volume, not with the number of users.  
5. **Filter by relevance:** for each subscribed project, build a call graph from its code into its dependencies, and alert only if the project actually reaches a fixed function.

**Evaluation:** replay real commit history against GitHub Security Advisories and other public databases, and measure:

* **Precision: when it rings, is there really a fire?** Out of all the commits PreCVE flags, how many are actually security fixes. Low precision means many false alarms.  
* **Recall: when there’s a fire, does it ring?** Out of all the real security fixes, how many PreCVE catches. Low recall means it misses real fixes.  
* **Lead time:** how many days before the first advisory each fix is detected.  
* **Cost and throughput** at scale.

# אפיון המוצר PreCVE

## תיאור הפרויקט

מערכת שמתריעה למפתחים על תיקוני אבטחה בספריות קוד פתוח שהפרויקט שלהם תלוי בהן, עוד לפני שהחולשות מתפרסמות במאגרי האבטחה הרשמיים (CVE, NVD, GHSA, OSV). 

## חווית המשתמש

**העלאה:**

1. נכנס לאתר ונרשם באמצעות מייל וסיסמא. (יכול גם להתנתק)  
2. המשתמש יוצר מעקב אחר פרויקט באמצעות הוספת שם הפרויקט והעלאת קובץ requirements.txt אל מקום מיועד באתר.  
3. המשתמש יכול לראות את כל הפרויקט עם התראות פעילות בדשבורד.  
4. המשתמש יכול לכבות התראות עבור כל פרויקט בנפרד.  
5. המשתמש יכול למחוק פרויקט.

**קבלת התראות:**

1. עבור כל פרויקט, ברגע שהמערכת מזהה שבוצע תיקון שקט לאחת הספריות בהן הפרויקט תלוי באופן ישיר היא שולחת למייל עדכון על כך, עם פרטי השינוי.  
2. העדכון נשלח רק אם התיקון רלוונטי עבור הגרסה שנמצאת ב-requirements.txt  
3. בהינתן התראה, המפתח:  
   1. בודק אם היא רלוונטית.  
   2. חוקר יותר לעומק מה החולשה ומה חומרתה.  
   3. מחליט האם לבצע patching מקומית אצלו עד שתצא גרסה רשמית.

### **הטכנולוגיות ומה כל אחת עושה**

* **Docker & Linux**: כדי להעלות את השרת ולעבוד על אותה סביבה.  
* **HTML, CSS, JavaScript**  
* **Git:** לניהול גרסאות   
* **AWS / GCP:** שזה יהיה באוויר  
* **Python**: שפת התכנות של כל הפרויקט, גם האתר וגם הגלאי.  
* **Django**: בונה את האתר: הרשמה והתחברות, דשבורד, העלאת קובץ requirements.txt, כיבוי התראות ומחיקת פרויקט, ושולחת את מיילי ההתראה.  
* **SQLite**: מסד הנתונים שבו נשמרים המשתמשים, הפרויקטים, התלויות, הקומיטים שנותחו וההתראות שנשלחו.  
* **PyDriller**: קוראת את הקומיטים של החבילות מ-GitHub ונותנת לנו את ההודעה, התאריך והשינויים של כל קומיט.  
* **LLMs**: כנראה הגלאי עצמו. מקבל קומיט ועונה אם הוא נראה כמו תיקון אבטחה, עם ציון ביטחון והסבר קצר.  
* **Machine Learning:** על מנת להשוות ולראות האם אפשר להשתמש בML ולחסוך חלק מהעובדה מהLLM  
* **GitHub Advisory Database ו-OSV**: מאגרי חולשות ציבוריים. משמשים כמקור לדוגמאות של תיקוני אבטחה ידועים לבדיקת הגלאי, ולמידע על הגרסאות הפגועות.

### **איך החלקים מתחברים**

1. המשתמש נרשם ומעלה requirements.txt ב-**Django**, וה-**SQLite** שומר את התלויות שלו (**Monolith Architecture)**.  
2. סקריפט מתוזמן (cron) מפעיל **PyDriller** על החבילות הנעקבות ומושך קומיטים חדשים.  
3. כל קומיט חדש נשלח ל-**LLM API**, והתוצאה נשמרת ב-SQLite.  
4. אם הקומיט חשוד, **Django** בודק אילו פרויקטים תלויים בחבילה בגרסה הרלוונטית, ושולח להם מייל.  
5. **GHSA ו-OSV** משמשים בשלב הבדיקה: דוגמאות של תיקונים ידועים לבדוק עליהן את הגלאי.

   [https\://semgrep.dev/?utm\_source=google\&utm\_medium=cpc\&utm\_campaign=22148880225\&utm\_content=797674418762\&utm\_term=semgrep\&gad\_source=1\&gad\_campaignid=22148880225\&gbraid=0AAAAAB3vytR\_XYCnv-VxLhqKmkQht\_E-A\&gclid=Cj0KCQjw3YvXBhCDARIsAKB-ox-QhPHt6q7Y0Cp7AD15hOClvXWugwNxaSoNkVbvU7rYxIC70p32iOMaAkjyEALw\_wcB](https://semgrep.dev/?utm_source=google&utm_medium=cpc&utm_campaign=22148880225&utm_content=797674418762&utm_term=semgrep&gad_source=1&gad_campaignid=22148880225&gbraid=0AAAAAB3vytR_XYCnv-VxLhqKmkQht_E-A&gclid=Cj0KCQjw3YvXBhCDARIsAKB-ox-QhPHt6q7Y0Cp7AD15hOClvXWugwNxaSoNkVbvU7rYxIC70p32iOMaAkjyEALw_wcB)5

### **תכנית עבודה 1**

**תכנית עבודה (200 שעות)**

1. ללמוד איך נראים vulnerabilities, כיצד הם נגרמים ואיך האקרים מנצלים אותם.  
2. ללמוד את הפורמט של advisories: מה זה CVSS score, ואיך נראית רשומה ב-CVE, NVD, GHSA ו-OSV.  
3. קיק-אוף: הקמת repo, סביבת Docker משותפת, והסכמה על מבנה ה-database ועל ה-contract של הגלאי.  
4. גודל הדאטה: כמה קומיטים יהיו ביום בממוצע ומה ה-peak. לבחור רשימה סגורה של ספריות נתמכות, כך שעלות ה-LLM לא תעבור \$10 לחודש.  
5. בדיקת היתכנות:  
   * לבנות dataset של advisories מ-GHSA עם קומיט תיקון מקושר, ועוד קומיטים רגילים מאותם repos.  
   * להשוות שתי גישות: חוקים/regex מול LLM.  
   * למדוד Precision, Recall ו-Lead time, ולבחור גלאי.  
6. ללמוד באופן בסיסי על:  
   * סיווג והערכה (precision, recall)  
   * pandas ו-Jupyter   
   * חוקים ו-regex  
   *  ML קלאסי, Embeddings.  
   * LLMs, כולל prompt injection  
7. ללמוד Django, Docker ו-SQL.  
8. פיתוח האתר ב-Django בסביבת Docker: הרשמה והתחברות עם django.contrib.auth, העלאת requirements.txt, דשבורד, כיבוי התראות ומחיקת פרויקט.  
9. שמירת נתוני המשתמשים ב-database, כולל התלויות של כל פרויקט. תלויות שלא ברשימה הנתמכת יסומנו "לא במעקב".  
10. סקריפט cron שמריץ PyDriller ושולף commits חדשים. כל קומיט מעובד פעם אחת בלבד (Idempotency).  
11. עיבוד commits בעזרת הגלאי, כולל contracts ו-retry logic, ושמירת התוצאות ב-database.  
12. שליחת התראות במייל לפי כלל גרסה פשוט: מתריעים אם הגרסה ב-requirements.txt שוחררה לפני קומיט התיקון, או אם הגרסה לא נעוצה. אותה התראה לא נשלחת פעמיים.  
13. כתיבת טסטים באופן שוטף.  
14. מדידות של המערכת: Precision, Recall, Lead time, עלות ליום ו-throughput.  
15. בניית תשתית ל-production:  
* שרת אחד עם Docker Compose  
* CI/CD פשוט ב-GitHub Actions, ישירות ל-prod  
* logging, ומייל כשה-cron נכשל  
* Final Deployment  
16. בדיקת end-to-end: להריץ מחדש קומיט תיקון ידוע ולוודא שהמייל מגיע.  
17. כתיבת Readme והכנת מצגת ליום הצגת הפרויקט.  
18. סנכרון שבועי של 15 דקות, לאורך 20 שבועות.  
19. באפר לעיכובים ודיבאגינג.  
    

מחוץ ל-200 השעות:

**שם הפרויקט:** PreCVE: Early Detection of Silent Security Fixes in Python Dependencies

**פרטי התלמידים:**

* תלמיד א': ישי כרמלי 212240303 ishaic@post.bgu.ac.il  
* תלמיד ב': תמיר דלבה 323818831 dalvat@post.bgu.ac.il

**פרטי המנחים:** להשלים.

**תיאור הפרויקט:**  
 מערכת שמתריעה למפתחים על תיקוני אבטחה שקטים בספריות Python שהפרויקט שלהם תלוי בהן, עוד לפני שהחולשות מתפרסמות במאגרי האבטחה הרשמיים (CVE, NVD, GHSA, OSV). המערכת סורקת קומיטים חדשים בספריות הנתמכות, ובעזרת גלאי מזהה קומיטים שנראים כמו תיקון אבטחה. לאחר מכן היא שולחת מייל לפרויקטים שתלויים בגרסה שעדיין לא תוקנה. הגלאי ייבחר בבדיקת היתכנות שתשווה בין גישות לפי Precision, Recall ו-Lead time.

**שפות תכנות / כלי תוכנה / טכנולוגיות:**

* שפות: Python, HTML, CSS, JavaScript  
* ספריות וכלים: Django, SQLite, PyDriller, LLM APIs, pandas, Jupyter  
* תשתית ונתונים: Docker, Linux, Git, GitHub Actions, AWS / GCP, GitHub Advisory Database, OSV

**תכנית עבודה – שלבי הפרויקט ולוח זמנים:**

| תקופה | Upstream | Downstream | משותף |
| ----: | ----: | ----: | ----: |
| נובמבר | יסודות הערכה, חוקים ו-regex, ML קלאסי, Embeddings ודמיון ו-LLMs. | לימוד Django, Docker ו-SQL. הערכת גודל הדאטה והעלות. | לימוד חולשות ופורמט advisories (CVE, NVD, GHSA, OSV, CVSS) |
| דצמבר – אמצע ינואר | בדיקת היתכנות: בניית dataset מ-GHSA,  השוואה בין גלאי חוקים/regex לגלאי LLM, מדידת Precision, Recall ו-Lead time ובחירת גלאי.pandas ו-Jupyter. | פיתוח האתר ב-Django: הרשמה, העלאת requirements.txt, דשבורד, כיבוי התראות ומחיקת פרויקט | בתחילת דצמבר, קיק-אוף: הקמת repo וסביבת Docker, והסכמה על מבנה ה-database ועל ה-contract של הגלאי |
| אמצע ינואר – סוף פברואר | תקופת מבחנים | תקופת מבחנים |  |
| מרץ | סקריפט cron עם PyDriller לשליפת קומיטים חדשים (Idempotency) | שמירת נתוני המשתמשים ב-database, כולל התלויות של כל פרויקט |  |
| אפריל | עיבוד הקומיטים בגלאי עם contracts ו-retry logic, ושמירת התוצאות | שליחת התראות במייל לפי כלל הגרסה, בלי התראות כפולות | בסוף אפריל: בדיקת end-to-end |
| מאי | מדידות הגלאי על המערכת החיה (Precision, Recall, Lead time) וטסטים | פריסה ל-production עם Docker Compose, CI/CD ו-logging, מדידת עלות ו-throughput, וטסטים |  |
| יוני |  |  | כתיבת README, הכנת מצגת, התכוננות ליום הצגת הפרויקטים, ובאפר לעיכובים |

**יום הצגת פרויקטים:** להשלים את התאריך.

* **נובמבר:** מחקר והכנה: היכרות עם חולשות ופורמט advisories (CVE, GHSA, OSV), בחינת שיטות זיהוי (regex, ML קלאסי, LLM), ולימוד הטכנולוגיות (Django, SQL).  
* **דצמבר – אמצע ינואר:** בניית סט נתונים מ-GHSA, השוואה בין גלאים ובחירת הגלאי (מדידת Precision, Recall ו-Lead time), ובמקביל פיתוח האתר: הרשמה, העלאת requirements.txt, דשבורד, כיבוי התראות ומחיקת פרויקט.  
* **אמצע ינואר – סוף פברואר:** תקופת מבחנים.  
* **מרץ:** סקריפט שמושך קומיטים חדשים של החבילות הנעקבות ושומר אותם במסד הנתונים, יחד עם נתוני המשתמשים והתלויות של כל פרויקט.  
* **אפריל:** עיבוד הקומיטים בגלאי ושמירת התוצאות, ושליחת התראות במייל לפי גרסת החבילה, בלי התראות כפולות. בסוף החודש בדיקה מקצה לקצה.  
* **מאי:** מדידת איכות הגלאי על המערכת החיה (Precision, Recall, Lead time), ומדידת עלות ותפוקה.  
* **יוני:** כתיבת README והכנת מצגת ליום הצגת הפרויקטים, ותיקונים אחרונים.

* **נובמבר:** מחקר: advisories (CVE, GHSA, OSV), שיטות זיהוי ולימוד Django.  
* **דצמבר – ינואר:** בניית סט נתונים, השוואת גלאים ובחירתו, ופיתוח האתר.  
* **ינואר – פברואר:** תקופת מבחנים.  
* **מרץ:** משיכת קומיטים חדשים ושמירתם במסד הנתונים.  
* **אפריל:** הרצת הגלאי ושליחת התראות במייל, ובדיקה מקצה לקצה.  
* **מאי:** מדידת Precision, Recall ו-Lead time על המערכת החיה.  
* **יוני:** README, מצגת והכנה ליום הצגת הפרויקטים.

זה 7 שורות, ויש מקום לאחת נוספת. אם יתברר שהטקסט עדיין גולש, שתי אפשרויות:

* למזג את מרץ ואפריל לשורה אחת: “**מרץ – אפריל:** משיכת קומיטים, הרצת הגלאי, שליחת התראות ובדיקה מקצה לקצה.”

### **תכנית עבודה – שלבי הפרויקט ולוח זמנים**

* ### **נובמבר: סקירה ולמידה של הנושא ושל הטכנולוגיות.**

* ### **דצמבר: סט נתונים מתויג של advisories, בחירת גלאי אופטימלי ומדידתו (Precision, Recall, Lead time).**

* ### **ינואר: אתר בסיסי עובד (הרשמה, העלאת requirements.txt, דשבורד) ותקופת מבחנים.**

* ### **מרץ: מערכת המושכת קומיטים חדשים, מבצעת עליהם את הבדיקות הנדרשות ושומרת פרטים על כך במסד הנתונים.**

* ### **אפריל: מערכת מלאה שמריצה את הגלאי ושולחת התראות במייל, בדוקה מקצה לקצה.**

* ### **מאי: מדידת איכות הגלאי על המערכת החיה, עם נתוני Precision, Recall, עלות ותפוקה.**

* ### **יוני: README, Deployment מצגת ומוצר סופי מוכן ליום הצגת הפרויקטים.**

### 

### 

### 

### **תכנית עבודה**

1. ללמוד איך נראים vulnerabilities, כיצד הם נגרמים ואיך האקרים מנצלים אותם.  
2. ללמוד על הפורמט עצמו של advisories בדאטה בייסים שונים: למשל מה זה CVSS score, ואיך נראית רשומה באתרים השונים CVE, NVD, GHSA, OSV.  
3. ללמוד באופן בסיסי על:  
   1. סיווג והערכה   
   2. pandas ו-Jupyter   
   3. חוקים ו-regex  
   4. ML קלאסי  
   5. Embeddings ודמיון   
   6. LLMs (כולל prompt injection)  
   7. RAG  
4. ללמוד על גודל הדאטה \- כמה קומיטים יהיו ביום בממוצע? מה הPeak? באיזה כמות משתמשים וספריות אנחנו מוכנים לתמוך? כמה זה יעלה? לבחור גבול עליון על כמות המשתמשים והספריות הנתמכות על מנת להשאיר את המערכת פשוטה.  
5. בדיקת היתכנות: לנסות מספר גישות שונות לניתוח silent fixes (ואולי לשלב ביניהם), לבחור מדגם של commits מספריות ומדגם של חולשות, ולבדוק שני דברים לגבי כל גישה:  
   1. Precision  
   2. Recall \- False Negatives  
   3. Lead time: how many days before the first advisory each fix is detected.  
6. ללמוד Django, Docker, SQL, HTML, CSS  
7. פיתוח השרת בDjango רק של ממשק האתר (הרשמה והוספת קבצים) בסביבת Docker  
8. שמירת נתוני המשתמשים ב- database כולל Package Requirements של הפרויקטים שלהם.  
9. בניית סקריפט אוטומטי בשרת שרץ באינטרוולים ושולף commits חדשים מספריות של המשתמשים (כל קומיט צריך להיות מעובד פעם אחת \- מדיניות Idempotency).  
10. עיבוד commits בעזרת הגלאי, כתיבת contracts ו-retry logic, ושמירת התוצאות ב database.  
11. שליחת התראות במייל \- Django בודק אילו פרויקטים תלויים בחבילה בגרסה הרלוונטית, ושולח להם מייל. יש למצוא דרך להתריע למשתמשים שרק הגרסה הנוכחית אצליהם מכילה גרסה לא מתוקנת.  
12. הוספת Auth.  
13. כתיבת טסטים באופן שוטף.  
14. הוספת מדידות של המערכת (Precision, Recall, Lead time, Cost and throughput)   
15. בניית תשתית לproduction:  
    1. מציאת שירות Hosting  
    2. בניית CI/CD pipline פשוט (ישירות לprod, אין staging)  
    3. ניהול גרסאות  
    4. מערך logging, monitoring וalerts \- מקום לאחסן ולמדוד את תפוקת המערכת.  
16.  Final Deployment.  
17. כתיבת Readme, יצירת מצגת התכוננות ליום הצגת הפרויקט.

# PreCVE 

LLM-Based Detection of Silent Security Fixes in Open-Source Dependencies of python applications.

## **שם הפרויקט**

PreCVE: Early Detection of Silent Security Fixes in Python Dependencies

## **תיאור הפרויקט**

A system that monitors commits in open-source PyPI packages and uses an LLM-based detector to flag likely silent security fixes before official advisories are published. Each upstream commit is analyzed once and shared across all subscribed projects, and a call-graph reachability analysis notifies a project only if its code actually reaches the fixed functions. Evaluated by replaying real commit history against GitHub Security Advisories, measuring precision, detection lead time, throughput, and cost.

## **שפות תכנות / כלי תוכנה / טכנולוגיות**

Python, Redis (task queues), PostgreSQL, Docker on Linux. LLM APIs (batch processing, prompt caching). PyDriller/git for commit history, Python `ast` and call-graph tools for reachability, static analyzers (Bandit/Semgrep), GitHub Advisory Database and OSV for ground truth.

**תכנית עבודה – שלבי הפרויקט ולוח זמנים**

1. **By Nov 1**: Research and pilot. Compare candidate detectors on known fixes vs. ordinary commits; select the detection approach.  
2. **By Nov 22**: MVP. Ingest commit history of selected PyPI repositories → queue → detector → PostgreSQL. Build the labeled set from the GitHub Advisory Database.  
3. **By Dec 13**: Historical replay as load generator; deduplication; metrics (throughput, cost per commit, precision, days before advisory). Reachability analysis v1: user code → package call graph → fixed functions.  
4. **By Jan 15**: Measurement-driven scaling (batching, caching, parallel workers), reliability (rate limits, bounded queues, crash recovery), project subscriptions and alerts, final evaluation and demo.

Adjust the dates if your course runs the full year.

