package ctfd

import (
	"context"
	"net/url"
	"strconv"
)

// paginate walks a paginated CTFd list endpoint, appending each page into all.
//
// It returns truncated=true when it stopped because MaxPages was reached
// rather than because the data ran out. Callers must surface that distinction:
// silently returning a partial scoreboard or user list as if it were complete
// is how a model ends up confidently reasoning about the wrong data.
//
// Only /users, /teams, /submissions, and /comments paginate in CTFd 3.7;
// /challenges, /scoreboard, /notifications, and the various /solves endpoints
// return complete arrays.
func paginate[T any](ctx context.Context, c *Client, path string, q url.Values, all *[]T) (bool, error) {
	if q == nil {
		q = url.Values{}
	} else {
		// Copy so a caller-owned map is not mutated with paging parameters.
		q = cloneValues(q)
	}
	q.Set("per_page", strconv.Itoa(c.opts.PerPage))

	for page := 1; page <= c.opts.MaxPages; page++ {
		q.Set("page", strconv.Itoa(page))

		var batch []T
		meta, err := c.get(ctx, path, q, &batch)
		if err != nil {
			return false, err
		}
		*all = append(*all, batch...)

		// No pagination metadata means the endpoint returned everything.
		if meta == nil || meta.Pagination == nil {
			return false, nil
		}
		if !meta.Pagination.HasNext() {
			return false, nil
		}
		// An empty page alongside a next pointer would loop forever.
		if len(batch) == 0 {
			return false, nil
		}
		if page == c.opts.MaxPages {
			c.log.Warn("stopped paginating at the configured limit",
				"path", path,
				"max_pages", c.opts.MaxPages,
				"fetched", len(*all),
				"total", meta.Pagination.Total,
			)
			return true, nil
		}
	}
	return true, nil
}

func cloneValues(q url.Values) url.Values {
	out := make(url.Values, len(q)+2)
	for k, v := range q {
		out[k] = append([]string(nil), v...)
	}
	return out
}
