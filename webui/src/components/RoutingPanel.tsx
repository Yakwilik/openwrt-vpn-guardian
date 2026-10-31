import { useEffect, useMemo, useRef, useState } from "react";
import type { ControlResponse, RoutingGroup, RoutingRule, RoutingState } from "../types";

const placeholders: Record<RoutingRule["type"], string> = {
  geosite: "telegram",
  domain: "example.com",
  full: "auth.example.com",
  regexp: "^cdn\\d+\\.example\\.com$",
  ip: "203.0.113.0/24",
  geoip: "us",
};

interface Draft {
  rules: RoutingRule[];
  groups: RoutingGroup[];
}

function routeKey(rule: RoutingRule): string {
  return rule.type + ":" + rule.value;
}

function newGroupID(existing: RoutingGroup[]): string {
  let id: string;
  do {
    id = "g" + Date.now().toString(36) + Math.random().toString(36).slice(2, 9);
  } while (existing.some((group) => group.id === id));
  return id;
}

function matchRule(rule: RoutingRule, query: string): boolean {
  return [rule.type, rule.value, rule.note ?? ""].some((text) =>
    text.toLocaleLowerCase().includes(query),
  );
}

export function RoutingPanel({
  control,
  busy,
  onSave,
}: {
  control?: ControlResponse;
  busy?: string;
  onSave: (rules: RoutingRule[], groups: RoutingGroup[]) => Promise<RoutingState | undefined>;
}) {
  const canManage = Boolean(control?.authenticated && control.authConfigured);
  const options = control?.routing?.options ?? [];
  const serverRules = control?.routing?.rules ?? [];
  const serverGroups = control?.routing?.groups ?? [];
  const serverSnapshot = JSON.stringify({ rules: serverRules, groups: serverGroups });
  const previousServerSnapshot = useRef(serverSnapshot);
  const [draft, setDraft] = useState<Draft>({ rules: serverRules, groups: serverGroups });

  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<Record<string, boolean>>(() => {
    try {
      const value = JSON.parse(window.localStorage.getItem("guardian.routing.expanded") ?? "{}");
      return value && typeof value === "object" && !Array.isArray(value) ? value : {};
    } catch {
      return {};
    }
  });

  useEffect(() => {
    try {
      window.localStorage.setItem("guardian.routing.expanded", JSON.stringify(expanded));
    } catch {
      // Private sessions can disable persistent storage; grouping still works.
    }
  }, [expanded]);
  const [type, setType] = useState<RoutingRule["type"]>("domain");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const [groupID, setGroupID] = useState("");
  const [groupFormOpen, setGroupFormOpen] = useState(false);
  const [newGroupName, setNewGroupName] = useState("");
  const [newGroupDescription, setNewGroupDescription] = useState("");
  const [editingGroupID, setEditingGroupID] = useState<string | null>(null);
  const [editingGroupName, setEditingGroupName] = useState("");
  const [editingGroupDescription, setEditingGroupDescription] = useState("");
  const [deleteGroupID, setDeleteGroupID] = useState<string | null>(null);
  const [editingRuleKey, setEditingRuleKey] = useState<string | null>(null);
  const [editedRule, setEditedRule] = useState<RoutingRule>();
  const [message, setMessage] = useState("");
  const addValueRef = useRef<HTMLInputElement>(null);

  // A background control refresh may return a newer snapshot. Only adopt it
  // automatically when the user has no unsaved changes.
  useEffect(() => {
    if (previousServerSnapshot.current === serverSnapshot) return;
    const previousSnapshot = previousServerSnapshot.current;
    setDraft((current) =>
      JSON.stringify(current) === previousSnapshot
        ? { rules: serverRules, groups: serverGroups }
        : current,
    );
    previousServerSnapshot.current = serverSnapshot;
  }, [serverSnapshot]);

  const dirty = JSON.stringify(draft) !== serverSnapshot;
  const query = search.trim().toLocaleLowerCase();
  const grouped = useMemo(() => {
    const ungrouped: RoutingGroup = {
      id: "",
      name: "Без группы",
      description: "Правила, которые ещё не распределены по группам",
    };
    const available = [...draft.groups];
    if (draft.rules.some((rule) => !rule.group)) available.push(ungrouped);
    return available.flatMap((group) => {
      const allRules = draft.rules.filter((rule) => (rule.group ?? "") === group.id);
      const groupMatch = query !== "" &&
        [group.name, group.description ?? ""].some((text) =>
          text.toLocaleLowerCase().includes(query),
        );
      const matching = query && !groupMatch
        ? allRules.filter((rule) => matchRule(rule, query))
        : allRules;
      if (query && !groupMatch && matching.length === 0) return [];
      return [{ ...group, count: allRules.length, matching }];
    });
  }, [draft, query]);

  function toggle(group: string) {
    setExpanded((current) => ({ ...current, [group]: !current[group] }));
  }

  function createGroup(event: React.FormEvent) {
    event.preventDefault();
    const name = newGroupName.trim();
    const description = newGroupDescription.trim();
    if (!name) return;
    if (draft.groups.some((group) => group.name.toLocaleLowerCase() === name.toLocaleLowerCase())) {
      setMessage("Группа с таким названием уже существует.");
      return;
    }
    const id = newGroupID(draft.groups);
    setDraft((current) => ({
      ...current,
      groups: [...current.groups, { id, name, ...(description ? { description } : {}) }],
    }));
    setGroupID(id);
    setExpanded((current) => ({ ...current, [id]: true }));
    setNewGroupName("");
    setNewGroupDescription("");
    setGroupFormOpen(false);
    setMessage("");
  }

  function beginEditGroup(group: RoutingGroup) {
    setEditingGroupID(group.id);
    setEditingGroupName(group.name);
    setEditingGroupDescription(group.description ?? "");
    setDeleteGroupID(null);
  }

  function updateGroup(event: React.FormEvent) {
    event.preventDefault();
    const name = editingGroupName.trim();
    const description = editingGroupDescription.trim();
    if (!name || !editingGroupID) return;
    if (draft.groups.some((group) => group.id !== editingGroupID &&
      group.name.toLocaleLowerCase() === name.toLocaleLowerCase())) {
      setMessage("Группа с таким названием уже существует.");
      return;
    }
    setDraft((current) => ({
      ...current,
      groups: current.groups.map((group) =>
        group.id === editingGroupID
          ? { ...group, name, description: description || undefined }
          : group,
      ),
    }));
    setEditingGroupID(null);
    setMessage("");
  }

  function removeGroup(id: string) {
    setDraft((current) => ({
      groups: current.groups.filter((group) => group.id !== id),
      // Deleting a group never deletes its routes.
      rules: current.rules.map((rule) =>
        rule.group === id ? { ...rule, group: undefined } : rule,
      ),
    }));
    if (groupID === id) setGroupID("");
    setDeleteGroupID(null);
    setExpanded((current) => ({ ...current, "": true }));
  }

  function addRule(event: React.FormEvent) {
    event.preventDefault();
    const normalized = value.trim();
    if (!normalized) return;
    if (draft.rules.some((rule) => routeKey(rule) === type + ":" + normalized)) {
      setMessage("Такое правило уже существует.");
      return;
    }
    const normalizedNote = note.trim();
    setDraft((current) => ({
      ...current,
      rules: [...current.rules, {
        type, value: normalized,
        ...(normalizedNote ? { note: normalizedNote } : {}),
        ...(groupID ? { group: groupID } : {}),
      }],
    }));
    setExpanded((current) => ({ ...current, [groupID]: true }));
    setValue("");
    setNote("");
    setMessage("");
  }

  function beginEditRule(rule: RoutingRule) {
    setEditingRuleKey(routeKey(rule));
    setEditedRule({ ...rule });
  }

  function updateRule(event: React.FormEvent) {
    event.preventDefault();
    if (!editedRule || !editingRuleKey) return;
    const updated = { ...editedRule, value: editedRule.value.trim(),
      note: editedRule.note?.trim() || undefined, group: editedRule.group || undefined };
    if (!updated.value) return;
    if (draft.rules.some((rule) =>
      routeKey(rule) !== editingRuleKey && routeKey(rule) === routeKey(updated))) {
      setMessage("Правило с таким типом и значением уже существует.");
      return;
    }
    setDraft((current) => ({
      ...current,
      rules: current.rules.map((rule) =>
        routeKey(rule) === editingRuleKey ? updated : rule,
      ),
    }));
    setEditingRuleKey(null);
    setEditedRule(undefined);
    setExpanded((current) => ({ ...current, [updated.group ?? ""]: true }));
    setMessage("");
  }

  function addToGroup(id: string) {
    setGroupID(id);
    addValueRef.current?.focus();
    addValueRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  async function save() {
    setMessage("");
    const updated = await onSave(draft.rules, draft.groups);
    if (!updated) {
      setMessage("Не удалось сохранить изменения. Проверь сообщение об ошибке.");
      return;
    }
    // The API returns the persisted canonical routing. Never display a
    // successful save based only on optimistic local state.
    setDraft({ rules: updated.rules, groups: updated.groups ?? [] });
    setEditingRuleKey(null);
    setEditingGroupID(null);
    setMessage("Сохранено. Правила и группы записаны на роутер.");
  }

  function reset() {
    setDraft({ rules: serverRules, groups: serverGroups });
    setEditingGroupID(null);
    setEditingRuleKey(null);
    setDeleteGroupID(null);
    setMessage("");
  }

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Маршруты через VPN</h2>
          <p>Группы для удобства. Маршрутизация определяется правилами, а не названием группы.</p>
        </div>
        <span className="panel-counter">{draft.rules.length} правил</span>
      </div>

      <div className="routing-toolbar">
        <input
          className="field"
          type="search"
          aria-label="Поиск по маршрутам и группам"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Найти группу, домен, IP или заметку..."
        />
        <button className="button button-quiet" type="button"
          onClick={() => setExpanded(Object.fromEntries(
            [...draft.groups.map((group) => group.id), ""].map((id) => [id, true]),
          ))}
        >Развернуть все</button>
        <button className="button button-quiet" type="button"
          onClick={() => setExpanded({})}
        >Свернуть все</button>
        {canManage && (
          <button className="button button-ghost" type="button"
            disabled={Boolean(busy)}
            onClick={() => setGroupFormOpen((current) => !current)}
          >+ Группа</button>
        )}
      </div>

      {canManage && groupFormOpen && (
        <form className="routing-group-editor" onSubmit={createGroup}>
          <input className="field" autoFocus maxLength={80}
            value={newGroupName} onChange={(event) => setNewGroupName(event.target.value)}
            placeholder="Название новой группы" required />
          <input className="field" maxLength={300}
            value={newGroupDescription}
            onChange={(event) => setNewGroupDescription(event.target.value)}
            placeholder="Общее описание группы" />
          <div className="row-actions">
            <button className="button button-primary" disabled={Boolean(busy) || !newGroupName.trim()}>
              Создать группу
            </button>
            <button className="button button-quiet" type="button"
              onClick={() => setGroupFormOpen(false)}>Отмена</button>
          </div>
        </form>
      )}

      {canManage && (
        <form className="routing-add" onSubmit={addRule}>
          <select className="field select" aria-label="Тип правила"
            value={type} onChange={(event) => setType(event.target.value as RoutingRule["type"])}>
            {options.map((option) => (
              <option value={option.value} key={option.value}>{option.label}</option>
            ))}
          </select>
          <input className="field mono" ref={addValueRef}
            value={value} onChange={(event) => setValue(event.target.value)}
            placeholder={placeholders[type]} required />
          <select className="field select" aria-label="Группа для нового правила"
            value={groupID} onChange={(event) => setGroupID(event.target.value)}>
            <option value="">Без группы</option>
            {draft.groups.map((group) => (
              <option key={group.id} value={group.id}>{group.name}</option>
            ))}
          </select>
          <input className="field routing-note-input" maxLength={200}
            value={note} onChange={(event) => setNote(event.target.value)}
            placeholder="Заметка (необязательно)" />
          <button className="button button-ghost" disabled={!value.trim() || Boolean(busy)}>
            Добавить
          </button>
        </form>
      )}
      {canManage && <div className="routing-add-caption">Добавление и редактирование меняют черновик. Для применения нажми «Сохранить».</div>}

      <div className="routing-groups">
        {grouped.map((group) => {
          const opened = Boolean(query) || Boolean(expanded[group.id]);
          const isUngrouped = !group.id;
          const editing = editingGroupID === group.id;
          const confirmingDelete = deleteGroupID === group.id;
          return (
            <div className="routing-group" key={group.id || "__ungrouped"}>
              <div className="routing-group-head">
                <button type="button" className="routing-group-toggle"
                  aria-expanded={opened}
                  onClick={() => toggle(group.id)}>
                  <span className="routing-chevron" aria-hidden="true">{opened ? "▾" : "▸"}</span>
                  <span className="routing-group-labels">
                    <strong>{group.name}</strong>
                    {group.description && <span className="routing-group-description">{group.description}</span>}
                  </span>
                  <span className="routing-group-count">{group.count}</span>
                </button>
                {canManage && !isUngrouped && (
                  <div className="routing-group-actions">
                    <button className="button button-quiet" type="button"
                      disabled={Boolean(busy)}
                      onClick={() => beginEditGroup(group)}>Изменить</button>
                    <button className="button button-danger-quiet button-small" type="button"
                      disabled={Boolean(busy)}
                      onClick={() => setDeleteGroupID(confirmingDelete ? null : group.id)}>Удалить</button>
                  </div>
                )}
              </div>

              {editing && (
                <form className="routing-group-editor" onSubmit={updateGroup}>
                  <input className="field" maxLength={80} aria-label="Новое название группы"
                    value={editingGroupName} onChange={(event) => setEditingGroupName(event.target.value)} required />
                  <input className="field" maxLength={300} aria-label="Описание группы"
                    value={editingGroupDescription}
                    onChange={(event) => setEditingGroupDescription(event.target.value)}
                    placeholder="Описание группы" />
                  <div className="row-actions">
                    <button className="button button-primary" disabled={!editingGroupName.trim() || Boolean(busy)}>Готово</button>
                    <button className="button button-quiet" type="button"
                      onClick={() => setEditingGroupID(null)}>Отмена</button>
                  </div>
                </form>
              )}
              {confirmingDelete && (
                <div className="routing-group-delete">
                  <span>Удалить группу? Её {group.count} правил останутся в разделе «Без группы».</span>
                  <button className="button button-danger" type="button"
                    disabled={Boolean(busy)} onClick={() => removeGroup(group.id)}>Удалить группу</button>
                  <button className="button button-quiet" type="button"
                    onClick={() => setDeleteGroupID(null)}>Отмена</button>
                </div>
              )}

              {opened && (
                <div className="routing-group-body">
                  {group.matching.map((rule) => {
                    const key = routeKey(rule);
                    if (editingRuleKey === key && editedRule) {
                      return (
                        <form className="routing-rule-editor" onSubmit={updateRule} key={key}>
                          <select className="field select" aria-label="Тип редактируемого правила"
                            value={editedRule.type}
                            onChange={(event) => setEditedRule({
                              ...editedRule, type: event.target.value as RoutingRule["type"],
                            })}>
                            {options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
                          </select>
                          <input className="field mono" aria-label="Значение правила"
                            value={editedRule.value} onChange={(event) => setEditedRule({
                              ...editedRule, value: event.target.value,
                            })} required />
                          <select className="field select" aria-label="Группа правила"
                            value={editedRule.group ?? ""}
                            onChange={(event) => setEditedRule({ ...editedRule, group: event.target.value || undefined })}>
                            <option value="">Без группы</option>
                            {draft.groups.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
                          </select>
                          <input className="field" maxLength={200} aria-label="Заметка правила"
                            value={editedRule.note ?? ""}
                            onChange={(event) => setEditedRule({ ...editedRule, note: event.target.value })}
                            placeholder="Заметка" />
                          <div className="row-actions">
                            <button className="button button-primary button-small" disabled={!editedRule.value.trim() || Boolean(busy)}>Готово</button>
                            <button className="button button-quiet" type="button" onClick={() => setEditingRuleKey(null)}>Отмена</button>
                          </div>
                        </form>
                      );
                    }
                    return (
                      <div className="routing-row" key={key}>
                        <span className="routing-type">{rule.type}</span>
                        <div className="routing-copy">
                          <span className="routing-value mono" title={rule.value}>{rule.value}</span>
                          {rule.note && <span className="routing-note" title={rule.note}>{rule.note}</span>}
                        </div>
                        {canManage && (
                          <div className="routing-row-actions">
                            <button className="button button-quiet" type="button"
                              disabled={Boolean(busy)} onClick={() => beginEditRule(rule)}>Изменить</button>
                            {!isUngrouped && (
                              <button className="button button-quiet" type="button"
                                disabled={Boolean(busy)}
                                onClick={() => setDraft((current) => ({
                                  ...current,
                                  rules: current.rules.map((item) =>
                                    routeKey(item) === key ? { ...item, group: undefined } : item,
                                  ),
                                }))}>Из группы</button>
                            )}
                            <button className="button button-danger-quiet button-small" type="button"
                              disabled={Boolean(busy)}
                              onClick={() => setDraft((current) => ({
                                ...current,
                                rules: current.rules.filter((item) => routeKey(item) !== key),
                              }))}>Удалить</button>
                          </div>
                        )}
                      </div>
                    );
                  })}
                  {group.count === 0 && <div className="routing-group-empty">Пока нет правил</div>}
                  {canManage && (
                    <button className="button button-quiet routing-add-to-group" type="button"
                      onClick={() => addToGroup(group.id)}>+ Добавить правило сюда</button>
                  )}
                </div>
              )}
            </div>
          );
        })}
        {grouped.length === 0 && (
          <div className="routing-group-empty">{query ? "По запросу ничего не найдено" : "Правил и групп пока нет"}</div>
        )}
      </div>

      {message && <div className="routing-feedback" role="status">{message}</div>}
      {canManage && (
        <div className="routing-footer">
          <span className="inline-note">
            {dirty ? "Есть несохранённые изменения" : "Все изменения сохранены"}
          </span>
          <div className="row-actions">
            <button className="button button-quiet" type="button"
              disabled={!dirty || Boolean(busy)} onClick={reset}>Сбросить</button>
            <button className="button button-primary" type="button"
              disabled={!dirty || Boolean(busy)}
              onClick={() => void save()}>
              {busy === "routing" ? "Сохранение..." : "Сохранить изменения"}
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
