import { useEffect, useState } from 'react'
import { isSessionAuthError } from '../../../../cmd/fullstack/client/index.js'

import { useAuth } from '../auth/AuthContext'
import { createTodo, deleteTodo, listTodos, updateTodo } from '../lib/todos'
import type { TodoItem } from '../types'

export function useTodos(enabled: boolean) {
  const auth = useAuth()
  const [items, setItems] = useState<TodoItem[]>([])
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function handleFailure(error: unknown, fallback: string) {
    const message = error instanceof Error ? error.message : fallback
    setError(message)
    if (error instanceof Error && isSessionAuthError(error)) {
      await auth.logout()
      setItems([])
    }
    throw error
  }

  async function refresh() {
    if (!enabled) {
      setItems([])
      setError('')
      return []
    }
    setLoading(true)
    setError('')
    try {
      const nextItems = await listTodos()
      setItems(nextItems)
      return nextItems
    } catch (error) {
      return handleFailure(error, 'Could not load items')
    } finally {
      setLoading(false)
    }
  }

  async function save(input: {
    id?: string
    title: string
    description: string
    done: boolean
    image_data_url?: string
    image_content_type?: string
  }) {
    setSaving(true)
    setError('')
    try {
      if (input.id) {
        await updateTodo(input.id, input)
      } else {
        await createTodo({
          title: input.title,
          description: input.description,
          image_data_url: input.image_data_url,
          image_content_type: input.image_content_type,
        })
      }
      await refresh()
    } catch (error) {
      await handleFailure(error, 'Could not save item')
    } finally {
      setSaving(false)
    }
  }

  async function remove(id: string) {
    setSaving(true)
    setError('')
    try {
      await deleteTodo(id)
      await refresh()
    } catch (error) {
      await handleFailure(error, 'Could not delete item')
    } finally {
      setSaving(false)
    }
  }

  useEffect(() => {
    if (!enabled) {
      setItems([])
      setError('')
      return
    }
    void refresh()
  }, [enabled])

  return {
    error,
    items,
    loading,
    refresh,
    remove,
    save,
    saving,
  }
}
