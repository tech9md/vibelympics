interface LoadingSkeletonProps {
  variant?: 'card' | 'text' | 'circle' | 'bar' | 'category';
  count?: number;
  className?: string;
}

export default function LoadingSkeleton({
  variant = 'card',
  count = 1,
  className = ''
}: LoadingSkeletonProps) {
  const items = Array.from({ length: count }, (_, i) => i);

  if (variant === 'card') {
    return (
      <>
        {items.map((i) => (
          <div
            key={i}
            className={`animate-pulse bg-slate-800/50 rounded-xl p-6 ${className}`}
          >
            <div className="flex items-start gap-4">
              <div className="w-12 h-12 bg-slate-700 rounded-lg shimmer" />
              <div className="flex-1 space-y-3">
                <div className="h-4 bg-slate-700 rounded w-3/4 shimmer" />
                <div className="h-3 bg-slate-700 rounded w-1/2 shimmer" />
              </div>
            </div>
          </div>
        ))}
      </>
    );
  }

  if (variant === 'category') {
    return (
      <>
        {items.map((i) => (
          <div
            key={i}
            className={`animate-pulse bg-slate-800/50 rounded-xl p-6 border border-slate-700 ${className}`}
          >
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-slate-700 rounded-lg shimmer" />
                <div className="space-y-2">
                  <div className="h-5 bg-slate-700 rounded w-32 shimmer" />
                  <div className="h-3 bg-slate-700 rounded w-24 shimmer" />
                </div>
              </div>
              <div className="w-16 h-8 bg-slate-700 rounded shimmer" />
            </div>
            <div className="space-y-2">
              <div className="h-3 bg-slate-700 rounded w-full shimmer" />
              <div className="h-3 bg-slate-700 rounded w-5/6 shimmer" />
            </div>
          </div>
        ))}
      </>
    );
  }

  if (variant === 'text') {
    return (
      <>
        {items.map((i) => (
          <div
            key={i}
            className={`h-4 bg-slate-700 rounded w-full shimmer ${className}`}
          />
        ))}
      </>
    );
  }

  if (variant === 'circle') {
    return (
      <>
        {items.map((i) => (
          <div
            key={i}
            className={`w-12 h-12 bg-slate-700 rounded-full shimmer ${className}`}
          />
        ))}
      </>
    );
  }

  if (variant === 'bar') {
    return (
      <>
        {items.map((i) => (
          <div
            key={i}
            className={`h-2 bg-slate-700 rounded-full w-full shimmer ${className}`}
          />
        ))}
      </>
    );
  }

  return null;
}
