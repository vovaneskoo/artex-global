package server

import (
	"context"
	"log"
	"strconv"
	"strings"
	"time"
)

// retest_auto.go — фоновый автопланировщик перепроверок подтверждённых находок
// (поверх существующего механизма finding_retests, без новых таблиц):
//
//   - цикл — ОДИН на процесс, лениво стартует из Engine.Run при запуске первой
//     задачи (идемпотентный флаг autoRetestOn, по образцу coordStarted/started);
//   - раз в интервал (дефолт 1ч, настройка retest_interval_minutes) делает один
//     проход: отбор находок через db.FindingsDueForRetest (status='confirmed' +
//     не было ретеста N дней, N=дефолт 14, настройка retest_after_days) и запуск
//     РОВНО ОДНОГО ретеста за проход (autoRetestPassLimit);
//   - запуск идёт через тот же серверный путь, что и API-хендлер —
//     s.launchFindingRetest (хук retestLauncher, подключается в server.New), так
//     что наследуются предусловия (агент retester enabled, оба инструмента
//     привязаны, LLM доступен), лок-порядок pg.CreateFindingRetest, занятие
//     chatBusy и агент retester. Голый pg.CreateTaskWithOptions не используется:
//     ретест — это беседа retester'а, а не задача-миссия;
//   - ошибки любого рода — лог и продолжение на следующем тике; ничего не паникует
//     (recover на проход), цикл живёт до отмены корневого ctx сервера.

const (
	// settingRetestIntervalMinutes — период прохода автопретестов в минутах.
	// "0"/"off" полностью выключают планировщик; пусто/невалидно → дефолт 1ч.
	// Паттерн чтения — TaskDefaultTimeout (manager.go): GetSetting → Atoi →
	// невалидное/отрицательное → дефолт.
	settingRetestIntervalMinutes = "retest_interval_minutes"
	// settingRetestAfterDays — через сколько дней без ретеста подтверждённая
	// находка снова попадает в отбор. "0" допустим (немедленный отбор);
	// пусто/невалидно → дефолт 14.
	settingRetestAfterDays = "retest_after_days"

	defaultRetestInterval  = time.Hour
	defaultRetestAfterDays = 14
	// autoRetestPassLimit — максимум ретестов, запускаемых за один проход: один.
	autoRetestPassLimit = 1
	// autoRetestPassTimeout — бюджет одного прохода (отбор + запуск ретеста).
	autoRetestPassTimeout = 2 * time.Minute
	// autoRetestDisabledPoll — период перепроверки настройки, пока планировщик
	// выключен: заметить повторное включение быстрее часового дефолта.
	autoRetestDisabledPoll = 5 * time.Minute
	// autoRetestFirstPassDelay — задержка до первого прохода после старта цикла:
	// дать серверу закончить бутч (профили, агенты), не ждать целый интервал.
	autoRetestFirstPassDelay = time.Minute
	// maxRetestInterval — верхняя граница retest_interval_minutes: сколь угодно
	// большое значение не должно превращаться в фактическое вечное отключение
	// (перезапуск настройки без рестарта сервиса).
	maxRetestInterval = 24 * time.Hour
)

// autoRetestNotes — маркер автоматического запуска: попадает в notes ретеста, а
// оттуда — в InitialMessage агента (двухмозговой вход, домен复测 на китайском) и в
// историю для человека. По нему автозапуски отличимы от ручных без правки схемы.
const autoRetestNotes = "系统自动复测：该漏洞已确认且长时间未复测，请独立验证其当前状态。"

// autoRetestIntervalFrom разбирает значение retest_interval_minutes: ok=false или
// пусто → дефолт 1ч; "0"/"off" (в любом регистре) → 0, т.е. выключено; нечисловое
// или отрицательное → дефолт; иначе N минут.
func autoRetestIntervalFrom(v string, ok bool) time.Duration {
	if !ok || strings.TrimSpace(v) == "" {
		return defaultRetestInterval
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "off":
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return defaultRetestInterval
	}
	return time.Duration(n) * time.Minute
}

// autoRetestAfterDaysFrom разбирает retest_after_days: ok=false/пусто → дефолт 14;
// "0" валиден (находка становится «due» сразу); нечисловое/отрицательное → дефолт.
func autoRetestAfterDaysFrom(v string, ok bool) int {
	if !ok || strings.TrimSpace(v) == "" {
		return defaultRetestAfterDays
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return defaultRetestAfterDays
	}
	return n
}

// autoRetestInterval читает настройку цикла; движок без БД (тестовые контексты)
// получает дефолт, как TaskDefaultTimeout при nil-pg.
func (e *Engine) autoRetestInterval() time.Duration {
	if e.m == nil || e.m.pg == nil {
		return defaultRetestInterval
	}
	v, ok, err := e.m.pg.GetSetting(settingRetestIntervalMinutes)
	if err != nil {
		return defaultRetestInterval
	}
	return autoRetestIntervalFrom(v, ok)
}

// autoRetestAfterDays читает окно перепроверки (nil-pg → дефолт 14).
func (e *Engine) autoRetestAfterDays() int {
	if e.m == nil || e.m.pg == nil {
		return defaultRetestAfterDays
	}
	v, ok, err := e.m.pg.GetSetting(settingRetestAfterDays)
	if err != nil {
		return defaultRetestAfterDays
	}
	return autoRetestAfterDaysFrom(v, ok)
}

// startAutoRetestLoop лениво и идемпотентно (CompareAndSwap по образцу
// coordStarted) поднимает единый на процесс фоновый цикл. Первый вызов — из
// Engine.Run при старте первой задачи; ctx — корневой контекст сервера (в
// продакшене s.ctx), цикл живёт до его отмены. Повторные вызовы — no-op.
func (e *Engine) startAutoRetestLoop(ctx context.Context) {
	if e == nil || !e.autoRetestOn.CompareAndSwap(false, true) {
		return
	}
	go e.autoRetestLoop(ctx)
}

// autoRetestLoop — сам цикл: короткая стартовая задержка → проход → спать
// интервал. Интервал перечитывается каждую итерацию (смена настройки применяется
// со следующего сна, с верхним потолком maxRetestInterval); выключение
// ("0"/"off") переводит цикл в тихий опрос настройки. recover покрывает сам
// проход; чтение настройки возвращает ошибку, а не паникует — цикл иммунен.
func (e *Engine) autoRetestLoop(ctx context.Context) {
	log.Printf("[retest-auto] фоновый цикл поднят (первый проход через %s, далее период %s)",
		autoRetestFirstPassDelay, defaultRetestInterval)
	if sleepCtx(ctx, autoRetestFirstPassDelay) {
		return
	}
	for {
		e.autoRetestPass(ctx)
		nap := e.autoRetestInterval()
		switch {
		case nap <= 0:
			nap = autoRetestDisabledPoll
		case nap > maxRetestInterval:
			nap = maxRetestInterval
		}
		if sleepCtx(ctx, nap) {
			return
		}
	}
}

// autoRetestPass — один проход: отбор находок, требующих перепроверки (ЛИМИТ 1
// ретест за проход), и запуск через серверный путь (retestLauncher → тот же
// launchFindingRetest, что дёргает API-хендлер). Любая ошибка — лог и ожидание
// следующего тика; created=false (активный ретест уже есть) — не ошибка. Паника
// прохода гасится recover, чтобы цикл пережил любой сбой.
func (e *Engine) autoRetestPass(ctx context.Context) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[retest-auto] проход упал (recover): %v", rec)
		}
	}()
	// Серверный путь не подключён (движок в тестовом окружении) — idle.
	if e.retestLauncher == nil || e.m == nil || e.m.pg == nil {
		return
	}
	afterDays := e.autoRetestAfterDays()
	pctx, cancel := context.WithTimeout(ctx, autoRetestPassTimeout)
	defer cancel()
	ids, err := e.m.pg.FindingsDueForRetest(pctx, afterDays, autoRetestPassLimit)
	if err != nil {
		log.Printf("[retest-auto] отбор находок (окно %d дн.): %v", afterDays, err)
		return
	}
	for _, id := range ids {
		created, err := e.retestLauncher(pctx, id, autoRetestNotes)
		switch {
		case err != nil:
			// Предусловия (агент/инструменты выключены, LLM нет) — ожидаемая
			// деградация: лог и следующая попытка на следующем тике.
			log.Printf("[retest-auto] находка %d: запуск ретеста не удался: %v", id, err)
		case created:
			log.Printf("[retest-auto] находка %d: автопретест запущен", id)
		default:
			// Активный ретест уже есть (дедуп на partial unique) — не ошибка.
		}
	}
}
