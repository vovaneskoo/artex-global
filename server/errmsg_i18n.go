package server

import "github.com/Autumn-27/artex/config"

// 사용자 대면 백엔드 메시지(한국어 원문)를 활성 출력 언어로 치환하는 카탈로그. 이 저장소의
// writeErr 응답 문구·일부 writeJSON 에러 필드는 한국어 상수·리터럴로 작성되어 있다(F3b/F34).
// 여기서는 그 한국어 원문을 키로, 영어·중국어·스페인어 번역을 값으로 둔다. 한국어(ko)는
// 키 자체이므로 저장하지 않고, 조회 실패·ko 일 때는 원문을 그대로 돌려준다.
//
// 키는 소스의 한국어 상수/리터럴에서 바이트 그대로 추출해 생성한다(scripts 보조). 손으로
// 타이핑하지 않으므로 writeErr 에 들어오는 런타임 값과 키가 어긋나 조용히 누락되는 일이 없다.
//
// 포맷 문자열 상수(%d·%s·%w 등)는 포매팅한 결과가 키와 달라지므로, 호출부에서 fmt.Sprintf/
// fmt.Errorf 에 넘기기 전에 trMsg(템플릿) 로 템플릿 자체를 먼저 치환한다.

// trMsg 는 한국어 원문 메시지를 활성 출력 언어로 치환한다. 카탈로그에 없거나 활성 언어가
// 한국어이면 원문을 그대로 돌려준다. config.ActiveLanguage 가 런타임 설정(설정 테이블)을
// 반영하므로, 사용자가 고른 언어가 즉시 적용된다.
func trMsg(ko string) string {
	if m, ok := errCatalog[ko]; ok {
		if v, ok2 := m[config.ActiveLanguage()]; ok2 && v != "" {
			return v
		}
	}
	return ko
}

// logT translates an operator-facing console log template (config.T) so server
// log.Printf sites can wrap a template without each file importing config.
func logT(ko string) string { return config.T(ko) }

// loadOutputLanguage resolves the user-facing output language from the source of
// truth: the runtime setting (settings table) over config.Language() (ARTEX_LANG >
// config file > ko). Call it only to (re)fill the cache; it does a DB query and a
// config file read.
func (s *Server) loadOutputLanguage() string {
	if s.m != nil && s.m.pg != nil {
		if v, ok, _ := s.m.pg.GetSetting(settingOutputLanguage); ok {
			if nv := config.NormalizeLanguage(v); nv != "" {
				return nv
			}
		}
	}
	return config.Language()
}

// outputLanguage returns the cached output language, resolving it on first use.
func (s *Server) outputLanguage() string {
	if v, ok := s.outputLang.Load().(string); ok && v != "" {
		return v
	}
	v := s.loadOutputLanguage()
	s.outputLang.Store(v)
	return v
}

// defaultTaskDescription is the placeholder stored when a task is created
// without a description (operator "new mission" body, spawn_task tool). It used
// to be the hardcoded Chinese "未命名任务", which leaked into every localized
// list/report under ru/en/etc. UI. Resolved from the operator's active output
// language; the ru wording matches report.ruBundle.unnamedTask.
func (s *Server) defaultTaskDescription() string {
	switch s.outputLanguage() {
	case "ru":
		return "Задача без названия"
	case "en":
		return "Unnamed task"
	case "zh":
		return "未命名任务"
	case "ja":
		return "名前のないタスク"
	case "es":
		return "Tarea sin nombre"
	default: // ko and anything unresolved
		return "이름 없는 작업"
	}
}

// seedIntentSummaryFmt is the template for the seed-first-intent summary shown
// in the task feed / worker list: %1$s = goal, %2$s = description. Previously a
// hardcoded Chinese template that leaked into localized UI (QA finding: the
// worker card on the task page showed "完成任务目标：…" under a ru locale).
func (s *Server) seedIntentSummaryFmt() string {
	switch s.outputLanguage() {
	case "ru":
		return "Выполнить цель задачи: %s (задача: %s)"
	case "en":
		return "Accomplish the task goal: %s (task: %s)"
	case "zh":
		return "完成任务目标：%s（任务：%s）"
	case "ja":
		return "タスクの目標を達成する: %s（タスク: %s）"
	case "es":
		return "Cumplir el objetivo de la tarea: %s (tarea: %s)"
	default: // ko and anything unresolved
		return "작업 목표 완수: %s (작업: %s)"
	}
}
