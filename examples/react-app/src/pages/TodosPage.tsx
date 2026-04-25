import { useState, type FormEvent } from 'react'

import { useTodos } from '../hooks/useTodos'
import type { TodoItem } from '../types'

type EditorState = {
  id: string
  title: string
  description: string
  done: boolean
  imageDataUrl: string
  imageContentType: string
}

const emptyEditor: EditorState = {
  id: '',
  title: '',
  description: '',
  done: false,
  imageDataUrl: '',
  imageContentType: '',
}

function mapTodoToEditor(item: TodoItem): EditorState {
  return {
    id: item.id,
    title: item.title,
    description: item.description,
    done: item.done,
    imageDataUrl: item.image_data_url || '',
    imageContentType: item.image_content_type || '',
  }
}

function readImageFile(file: File) {
  return new Promise<{ dataUrl: string; contentType: string }>((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(new Error('Could not read image.'))
    reader.onload = () => {
      if (typeof reader.result !== 'string') {
        reject(new Error('Could not read image.'))
        return
      }
      resolve({
        dataUrl: reader.result,
        contentType: file.type,
      })
    }
    reader.readAsDataURL(file)
  })
}

export function TodosPage() {
  const todos = useTodos(true)
  const [editor, setEditor] = useState<EditorState>(emptyEditor)
  const [imageError, setImageError] = useState('')

  const total = todos.items.length
  const done = todos.items.filter((item) => item.done).length
  const open = total - done

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    await todos.save({
      id: editor.id,
      title: editor.title,
      description: editor.description,
      done: editor.done,
      image_data_url: editor.imageDataUrl,
      image_content_type: editor.imageContentType,
    })
    setEditor(emptyEditor)
    setImageError('')
  }

  async function handleImageChange(file?: File) {
    if (!file) {
      return
    }
    setImageError('')
    if (!file.type.startsWith('image/')) {
      setImageError('Please choose an image file.')
      return
    }
    if (file.size > 2 * 1024 * 1024) {
      setImageError('Image must be 2MB or smaller.')
      return
    }
    try {
      const image = await readImageFile(file)
      setEditor((current) => ({
        ...current,
        imageDataUrl: image.dataUrl,
        imageContentType: image.contentType,
      }))
    } catch (error) {
      setImageError(error instanceof Error ? error.message : 'Could not read image.')
    }
  }

  return (
    <div className="page-stack">
      <section className="hero-panel">
        <div>
          <p className="eyebrow">Encrypted CRUD</p>
          <h2>Todo workspace</h2>
          <p className="lede">
            All create, update, and delete actions flow through the secure HTTP bridge after login.
          </p>
        </div>
        <div className="metric-grid">
          <article className="metric-card">
            <span className="metric-label">Total</span>
            <strong>{total}</strong>
          </article>
          <article className="metric-card">
            <span className="metric-label">Open</span>
            <strong>{open}</strong>
          </article>
          <article className="metric-card">
            <span className="metric-label">Done</span>
            <strong>{done}</strong>
          </article>
        </div>
      </section>

      <section className="workspace-grid">
        <form className="panel editor-panel" onSubmit={handleSubmit}>
          <div className="panel-header">
            <h3>{editor.id ? 'Edit item' : 'Create item'}</h3>
            <button
              type="button"
              className="secondary-button"
              onClick={() => setEditor(emptyEditor)}
            >
              Clear
            </button>
          </div>

          <label className="field">
            <span>Title</span>
            <input
              value={editor.title}
              onChange={(event) => setEditor((current) => ({ ...current, title: event.target.value }))}
              maxLength={120}
              required
            />
          </label>

          <label className="field">
            <span>Description</span>
            <textarea
              rows={5}
              value={editor.description}
              onChange={(event) =>
                setEditor((current) => ({ ...current, description: event.target.value }))
              }
            />
          </label>

          <label className="field">
            <span>Image</span>
            <input
              type="file"
              accept="image/png,image/jpeg,image/webp,image/gif"
              onChange={(event) => {
                const file = event.target.files?.[0]
                event.target.value = ''
                void handleImageChange(file)
              }}
            />
          </label>

          {(editor.imageDataUrl || imageError) && (
            <div className="image-stack">
              {editor.imageDataUrl && (
                <div className="image-preview-card">
                  <img className="todo-image-preview" src={editor.imageDataUrl} alt="" />
                  <button
                    type="button"
                    className="secondary-button"
                    onClick={() => {
                      setEditor((current) => ({
                        ...current,
                        imageDataUrl: '',
                        imageContentType: '',
                      }))
                      setImageError('')
                    }}
                  >
                    Remove image
                  </button>
                </div>
              )}
              {imageError && <div className="notice error">{imageError}</div>}
            </div>
          )}

          <label className="check-row">
            <input
              type="checkbox"
              checked={editor.done}
              disabled={!editor.id}
              onChange={(event) => setEditor((current) => ({ ...current, done: event.target.checked }))}
            />
            <span>Completed</span>
          </label>

          {todos.error && <div className="notice error">{todos.error}</div>}

          <button type="submit" className="primary-button" disabled={todos.saving}>
            {todos.saving ? 'Saving...' : editor.id ? 'Update item' : 'Create item'}
          </button>
        </form>

        <section className="panel list-panel">
          <div className="panel-header">
            <h3>Items</h3>
            <button
              type="button"
              className="secondary-button"
              onClick={() => void todos.refresh()}
              disabled={todos.loading}
            >
              {todos.loading ? 'Refreshing...' : 'Refresh'}
            </button>
          </div>

          {todos.items.length === 0 && !todos.loading ? (
            <div className="empty-state">No items yet.</div>
          ) : (
            <ul className="todo-list">
              {todos.items.map((item) => (
                <li key={item.id} className="todo-row">
                  <div className="todo-copy">
                    {item.image_data_url && (
                      <img className="todo-image" src={item.image_data_url} alt="" />
                    )}
                    <div className="todo-heading">
                      <h4>{item.title}</h4>
                      <span className={item.done ? 'badge done' : 'badge open'}>
                        {item.done ? 'Done' : 'Open'}
                      </span>
                    </div>
                    <p>{item.description || 'No description'}</p>
                    <span className="timestamp">
                      Updated {new Date(item.updated_at).toLocaleString()}
                    </span>
                  </div>
                  <div className="row-actions">
                    <button
                      type="button"
                      className="secondary-button"
                      onClick={() => setEditor(mapTodoToEditor(item))}
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      className="secondary-button"
                      onClick={() =>
                        void todos.save({
                          id: item.id,
                          title: item.title,
                          description: item.description,
                          done: !item.done,
                          image_data_url: item.image_data_url,
                          image_content_type: item.image_content_type,
                        })
                      }
                    >
                      {item.done ? 'Mark open' : 'Mark done'}
                    </button>
                    <button
                      type="button"
                      className="danger-button"
                      onClick={() => void todos.remove(item.id)}
                    >
                      Delete
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>
      </section>
    </div>
  )
}
